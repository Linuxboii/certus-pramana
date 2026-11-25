# certus-pramana

Check TLS certificates on live hosts or in local PEM files: expiry, names, issuer, chain trust, protocol and cipher, with CI-friendly exit codes.

*certus* (Latin, certain, sure) + *pramana* (Sanskrit, proof, means of valid knowledge) - proof that a certificate is what it claims to be.

> Only scan systems you own or are authorized to test.

## Features

- **Live checks** over a real TLS handshake: subject, issuer, DNS and IP SANs, validity window, days to expiry, serial, SHA-256 fingerprint, OCSP / CA-issuer / CRL URLs, negotiated protocol version and cipher.
- **Chain verification** against the system trust store. If verification fails the certificate is still fetched and reported, with the reason (`self-signed certificate`, `certificate has expired`, ...).
- **Hostname matching** done separately so mismatches are reported rather than aborting: exact names, a wildcard only as the whole left-most label (never `*.com`), IP addresses only against IP SANs.
- **Thresholds**: `--warn-days` (default 30) and `--crit-days` (default 7); not-yet-valid certificates, deprecated protocols (SSLv3, TLS 1.0/1.1) and ciphers under 128 bits are flagged too.
- **Batch mode**: a file of `host`, `host:port`, `[v6]:port`, `host port` or `https://` URLs, checked in parallel, with a summary line.
- **PEM files and bundles** (`--pem`), parsed with `ssl._ssl._test_decode_cert` - no network needed. `--hostname` checks the leaf against a name.
- Exit status **0** ok, **1** warning, **2** critical / expired / error, which drops into cron, CI or Nagios-style monitoring. `--json` for everything else.
- Standard library only. Defaults to `localhost:443` when no target is given.

## Install

```sh
pip install .
# or without installing
python -m certus_pramana --help
```

## Usage

```sh
certus-pramana example.com
certus-pramana mail.example.com:465 https://intranet.example.com:8443/
certus-pramana -f hosts.txt --warn-days 21 --crit-days 7
certus-pramana -f hosts.txt --json > report.json
certus-pramana --pem /etc/ssl/certs/server.pem --hostname www.example.com
certus-pramana staging.internal --servername app.example.com --no-verify
```

Single host:

```text
$ certus-pramana example.com
OK      example.com:443  expires in 89 day(s) (2027-02-22)
  Subject     CN=example.com
  Issuer      C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
  SANs        example.com, *.example.com
  Valid       2026-11-24 23:48 -> 2027-02-22 23:53 UTC
  Expires     in 89 day(s)
  Serial      77288510DF7E2B1D5B1EBC349A11DB61
  SHA-256     56986996436e5efd8e9355479c92c97ac3a5c1d25699783239674cb44d0c5220
  OCSP        http://o.cf-i.ssl.com
  CA issuers  http://i.cf-i.ssl.com/Cloudflare-TLS-I-E3.cer
  CRL         http://c.cf-i.ssl.com/ae801ed1c55bb579d79208b0d772acfb8cc3a208.crl
  Protocol    TLSv1.3  TLS_AES_256_GCM_SHA384 (256 bits)
  Chain       trusted
  Hostname    matches
```

Batch mode, using the public [badssl.com](https://badssl.com) test endpoints:

```text
$ cat hosts.txt
# public test endpoints
example.com
expired.badssl.com
wrong.host.badssl.com
self-signed.badssl.com
localhost:9

$ certus-pramana -f hosts.txt
OK      example.com:443  expires in 89 day(s) (2027-02-22)
EXPIRED expired.badssl.com:443  certificate expired 4244 day(s) ago (2015-04-12)
        - certificate chain not trusted: certificate has expired
CRIT    wrong.host.badssl.com:443  hostname 'wrong.host.badssl.com' does not match certificate names (*.badssl.com, badssl.com)
CRIT    self-signed.badssl.com:443  certificate chain not trusted: self-signed certificate
ERROR   localhost:9  connection failed: No connection could be made because the target machine actively refused it

5 target(s): 1 ok, 2 critical, 1 expired, 1 error
$ echo $?
2
```

Local PEM bundle (the test fixtures shipped in `tests/fixtures/`):

```text
$ certus-pramana --pem tests/fixtures/bundle.pem --hostname api.example.test
OK      tests/fixtures/bundle.pem #0  example.test
  Subject     C=US, O=Example Org, CN=example.test
  Issuer      C=US, O=Certus Test CA, CN=Certus Test Root
  SANs        example.test, *.example.test, 127.0.0.1
  Valid       2026-11-25 07:29 -> 2027-12-27 07:29 UTC
  Expires     in 396 day(s)
  Serial      30B9BABC8E9AAEB33E853766B77F28A6492FA963
  SHA-256     abc0ba028d74e4cd6f000c123151828087769412b9f309e1110b7375ea051a79
  OCSP        http://ocsp.example.test
  CA issuers  http://ca.example.test/ca.crt
  CRL         http://crl.example.test/root.crl

OK      tests/fixtures/bundle.pem #1  Certus Test Root
  Subject     C=US, O=Certus Test CA, CN=Certus Test Root
  Issuer      C=US, O=Certus Test CA, CN=Certus Test Root  (self-signed)
  SANs        (none)
  Valid       2026-11-25 07:29 -> 2036-11-22 07:29 UTC
  Expires     in 3649 day(s)
  Serial      3AB5115B7EE5C2950279A78EC7B4695E5E42A29F
  SHA-256     264acdac7e239afc80ca816fbe5e23a00db7abb5fb21bc8365555ad5a2e782f0
```

### Cron / CI

```sh
certus-pramana -f hosts.txt --warn-days 21 || notify-team "TLS certificates need attention"
```

## How it works

1. A verifying handshake is attempted first (system CAs, hostname check disabled so the name can be evaluated independently). On a verification error the reason is kept and an unverified handshake retrieves the certificate anyway.
2. The peer certificate is taken in DER form, converted to PEM and decoded with the ssl module's built-in X.509 parser (`ssl._ssl._test_decode_cert`), the same one behind `getpeercert()`. This works whether or not the chain was trusted.
3. Expiry, validity window, hostname, trust, protocol and cipher checks each raise the status to `warning`, `critical` or `expired`; the worst status across all targets becomes the exit code.

Note: `ssl._ssl._test_decode_cert` is an undocumented CPython helper. It has been stable for many releases, but it is not a public API.

## Running the tests

```sh
python -m unittest discover -s tests
```

Tests use the bundled fixture certificates and a fake connector - they never open a network connection.

## License

MIT - see [LICENSE](LICENSE).
