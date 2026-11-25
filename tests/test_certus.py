import datetime as dt
import io
import json
import os
import ssl
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from certus_pramana import certinfo, cli, probe
from certus_pramana.targets import parse_target, parse_targets_file

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
LEAF = os.path.join(FIX, "leaf.pem")
CA = os.path.join(FIX, "ca.pem")
BUNDLE = os.path.join(FIX, "bundle.pem")


def leaf():
    return certinfo.load_pem_file(LEAF)[0]


class HostnameTests(unittest.TestCase):
    def test_exact_and_case_insensitive(self):
        self.assertTrue(certinfo.hostname_matches("Example.TEST", ["example.test"]))

    def test_wildcard_single_label_only(self):
        sans = ["*.example.test"]
        self.assertTrue(certinfo.hostname_matches("www.example.test", sans))
        self.assertFalse(certinfo.hostname_matches("a.b.example.test", sans))
        self.assertFalse(certinfo.hostname_matches("example.test", sans))

    def test_wildcard_not_allowed_on_public_suffix_like_names(self):
        self.assertFalse(certinfo.hostname_matches("evil.com", ["*.com"]))
        self.assertFalse(certinfo.hostname_matches("x.y", ["*"]))

    def test_ip_addresses_only_match_ip_sans(self):
        self.assertTrue(certinfo.hostname_matches("127.0.0.1", [], ips=["127.0.0.1"]))
        self.assertFalse(certinfo.hostname_matches("127.0.0.1", ["127.0.0.1"]))
        self.assertTrue(certinfo.hostname_matches("::1", [], ips=["0:0:0:0:0:0:0:1"]))


class PemTests(unittest.TestCase):
    def test_leaf_fields(self):
        c = leaf()
        self.assertEqual(c.subject["commonName"], "example.test")
        self.assertEqual(c.issuer["organizationName"], "Certus Test CA")
        self.assertEqual(c.dns_names, ["example.test", "*.example.test"])
        self.assertEqual(c.ip_addresses, ["127.0.0.1"])
        self.assertFalse(c.self_signed)
        self.assertEqual(c.ocsp, ["http://ocsp.example.test"])
        self.assertEqual(len(c.sha256), 64)
        self.assertGreater(c.not_after, c.not_before)

    def test_bundle_has_two_certs_and_ca_is_self_signed(self):
        certs = certinfo.load_pem_file(BUNDLE)
        self.assertEqual(len(certs), 2)
        self.assertTrue(certs[1].self_signed)
        self.assertEqual(certs[0].sha256, leaf().sha256)

    def test_der_roundtrip(self):
        with open(LEAF) as fh:
            der = ssl.PEM_cert_to_DER_cert(fh.read())
        self.assertEqual(certinfo.decode_der(der).serial, leaf().serial)

    def test_not_a_pem(self):
        fd, path = tempfile.mkstemp(suffix=".pem")
        os.write(fd, b"hello")
        os.close(fd)
        try:
            with self.assertRaises(ValueError):
                certinfo.load_pem_file(path)
        finally:
            os.unlink(path)


class StatusTests(unittest.TestCase):
    def test_days_left_and_status_levels(self):
        c = leaf()
        na = c.not_after
        cases = [
            (na - dt.timedelta(days=100), "ok"),
            (na - dt.timedelta(days=20), "warning"),
            (na - dt.timedelta(days=3), "critical"),
            (na + dt.timedelta(days=1), "expired"),
            (c.not_before - dt.timedelta(days=1), "critical"),  # not yet valid
        ]
        for now, expected in cases:
            with self.subTest(expected=expected):
                status, _ = certinfo.evaluate(c, now=now, warn_days=30, crit_days=7)
                self.assertEqual(status, expected)
        self.assertEqual(c.days_left(na - dt.timedelta(days=10, hours=5)), 10)

    def test_hostname_mismatch_is_critical(self):
        c = leaf()
        now = c.not_before + dt.timedelta(days=1)
        status, problems = certinfo.evaluate(c, now=now, hostname="other.test")
        self.assertEqual(status, "critical")
        self.assertTrue(any("hostname" in p for p in problems))
        self.assertEqual(certinfo.evaluate(c, now=now, hostname="api.example.test")[0], "ok")


class TargetTests(unittest.TestCase):
    def test_parse_target_forms(self):
        self.assertEqual(parse_target("example.com"), ("example.com", 443))
        self.assertEqual(parse_target("example.com:8443"), ("example.com", 8443))
        self.assertEqual(parse_target("https://example.com/path?q=1"), ("example.com", 443))
        self.assertEqual(parse_target("https://example.com:9443/"), ("example.com", 9443))
        self.assertEqual(parse_target("[::1]:4443"), ("::1", 4443))
        self.assertEqual(parse_target("smtp.example.com 465"), ("smtp.example.com", 465))
        with self.assertRaises(ValueError):
            parse_target("host:notaport")

    def test_targets_file(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write("# prod\nexample.com\n\napi.example.com:8443  # trailing comment\n")
        try:
            self.assertEqual(parse_targets_file(path), [("example.com", 443), ("api.example.com", 8443)])
        finally:
            os.unlink(path)


def fake_connector(der, version="TLSv1.3", verified=True, error=None):
    def connect(host, port, timeout, servername, verify):
        return probe.Handshake(der=der, version=version, cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                               verified=verified, verify_error=error)
    return connect


class ProbeAndCliTests(unittest.TestCase):
    def setUp(self):
        with open(LEAF) as fh:
            self.der = ssl.PEM_cert_to_DER_cert(fh.read())
        self.now = leaf().not_before + dt.timedelta(days=2)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_check_host_ok(self):
        r = probe.check_host("www.example.test", 443, connector=fake_connector(self.der), now=self.now)
        self.assertEqual(r.status, "ok")
        self.assertTrue(r.hostname_ok)
        self.assertEqual(r.handshake.version, "TLSv1.3")
        self.assertEqual(r.to_dict()["certificate"]["subject"]["commonName"], "example.test")

    def test_untrusted_chain_and_old_protocol(self):
        r = probe.check_host("example.test", 443, now=self.now,
                             connector=fake_connector(self.der, version="TLSv1", verified=False,
                                                      error="self-signed certificate in certificate chain"))
        self.assertEqual(r.status, "critical")
        joined = " ".join(r.problems)
        self.assertIn("self-signed", joined)
        self.assertIn("TLSv1", joined)

    def test_connection_error(self):
        def boom(*a, **k):
            raise ConnectionRefusedError(10061, "refused")
        r = probe.check_host("example.test", 443, connector=boom, now=self.now)
        self.assertEqual(r.status, "error")
        self.assertIsNone(r.cert)

    def test_cli_batch_json_and_exit_code(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write("www.example.test\nwrong.host:8443\n")
        try:
            with mock.patch.object(probe, "default_connector", fake_connector(self.der)), \
                 mock.patch.object(certinfo, "utcnow", return_value=self.now):
                code, out, _ = self.run_cli("--file", path, "--json")
        finally:
            os.unlink(path)
        data = json.loads(out)
        self.assertEqual([r["status"] for r in data["results"]], ["ok", "critical"])
        self.assertEqual(data["results"][1]["port"], 8443)
        self.assertEqual(code, 2)

    def test_cli_pem_mode_text(self):
        with mock.patch.object(certinfo, "utcnow", return_value=self.now):
            code, out, _ = self.run_cli("--pem", BUNDLE, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("example.test", out)
        self.assertIn("Certus Test Root", out)
        self.assertIn("*.example.test", out)

    def test_cli_warn_threshold_exit_1(self):
        late = leaf().not_after - dt.timedelta(days=10)
        with mock.patch.object(certinfo, "utcnow", return_value=late):
            code, out, _ = self.run_cli("--pem", LEAF, "--warn-days", "30", "--crit-days", "5", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["results"][0]["status"], "warning")


if __name__ == "__main__":
    unittest.main()
