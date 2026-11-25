"""Certificate decoding, hostname matching and expiry evaluation."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import re
import ssl
import tempfile
from dataclasses import dataclass, field

STATUS_RANK = {"ok": 0, "warning": 1, "critical": 2, "expired": 3, "error": 4}
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.DOTALL)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _name_dict(rdns) -> dict:
    out: dict = {}
    for rdn in rdns or ():
        for key, value in rdn:
            out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def _cert_time(value: str) -> dt.datetime:
    return dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value), dt.timezone.utc)


_SHORT = {"commonName": "CN", "organizationName": "O", "organizationalUnitName": "OU", "countryName": "C",
          "stateOrProvinceName": "ST", "localityName": "L", "emailAddress": "E"}


def format_name(name: dict) -> str:
    return ", ".join(f"{_SHORT.get(k, k)}={v}" for k, v in name.items()) or "(empty)"


@dataclass
class CertInfo:
    subject: dict
    issuer: dict
    not_before: dt.datetime
    not_after: dt.datetime
    serial: str
    version: int | None
    sha256: str
    dns_names: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    ocsp: list[str] = field(default_factory=list)
    ca_issuers: list[str] = field(default_factory=list)
    crl: list[str] = field(default_factory=list)

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer

    @property
    def common_name(self) -> str | None:
        return self.subject.get("commonName")

    def days_left(self, now: dt.datetime | None = None) -> int:
        now = now or utcnow()
        return (self.not_after - now).days

    def to_dict(self, now: dt.datetime | None = None) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "subject_alt_names": {"dns": self.dns_names, "ip": self.ip_addresses},
            "not_before": self.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_left": self.days_left(now),
            "serial": self.serial,
            "version": self.version,
            "sha256": self.sha256,
            "self_signed": self.self_signed,
            "ocsp": self.ocsp,
            "ca_issuers": self.ca_issuers,
            "crl_distribution_points": self.crl,
        }


def from_decoded(d: dict, der: bytes) -> CertInfo:
    dns, ips = [], []
    for kind, value in d.get("subjectAltName", ()):
        if kind == "DNS":
            dns.append(value)
        elif kind == "IP Address":
            ips.append(value.strip())
    return CertInfo(
        subject=_name_dict(d.get("subject")),
        issuer=_name_dict(d.get("issuer")),
        not_before=_cert_time(d["notBefore"]),
        not_after=_cert_time(d["notAfter"]),
        serial=d.get("serialNumber", ""),
        version=d.get("version"),
        sha256=hashlib.sha256(der).hexdigest(),
        dns_names=dns,
        ip_addresses=ips,
        ocsp=list(d.get("OCSP", ())),
        ca_issuers=list(d.get("caIssuers", ())),
        crl=list(d.get("crlDistributionPoints", ())),
    )


def decode_der(der: bytes) -> CertInfo:
    """Decode a DER certificate using the ssl module's own X.509 parser.

    ``ssl._ssl._test_decode_cert`` only accepts a PEM file path, so the
    certificate is written to a short-lived temporary file.
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem", prefix="certus-")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pem)
        decoded = ssl._ssl._test_decode_cert(path)
    except ssl.SSLError as exc:
        raise ValueError(f"could not parse certificate: {exc}") from None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return from_decoded(decoded, der)


def load_pem_text(text: str) -> list[CertInfo]:
    blocks = _PEM_RE.findall(text)
    if not blocks:
        raise ValueError("no PEM certificate blocks found")
    certs = []
    for block in blocks:
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
        except ValueError as exc:
            raise ValueError(f"invalid PEM block: {exc}") from None
        certs.append(decode_der(der))
    return certs


def load_pem_file(path: str) -> list[CertInfo]:
    with open(path, encoding="ascii", errors="replace") as fh:
        try:
            return load_pem_text(fh.read())
        except ValueError as exc:
            raise ValueError(f"{path}: {exc}") from None


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def hostname_matches(host: str, dns_names: list[str], ips: list[str] | None = None) -> bool:
    """RFC 6125 style matching: exact names, or a wildcard as the whole left-most label.

    Wildcards must cover exactly one label and need at least two labels after
    them (``*.com`` never matches). IP addresses only match IP SAN entries.
    """
    ip = _as_ip(host)
    if ip is not None:
        return any(_as_ip(v) == ip for v in (ips or []))
    host = host.lower().rstrip(".")
    host_labels = host.split(".")
    for name in dns_names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        labels = name.split(".")
        if labels[0] == "*" and len(labels) >= 3 and "*" not in ".".join(labels[1:]):
            if len(host_labels) == len(labels) and host_labels[1:] == labels[1:] and host_labels[0]:
                return True
    return False


def worst(a: str, b: str) -> str:
    return a if STATUS_RANK[a] >= STATUS_RANK[b] else b


def evaluate(cert: CertInfo, now: dt.datetime | None = None, warn_days: int = 30, crit_days: int = 7,
             hostname: str | None = None) -> tuple[str, list[str]]:
    """Return ``(status, problems)``; status is ok / warning / critical / expired."""
    now = now or utcnow()
    status, problems = "ok", []
    days = cert.days_left(now)
    if now > cert.not_after:
        status = "expired"
        problems.append(f"certificate expired {(now - cert.not_after).days} day(s) ago "
                        f"({cert.not_after:%Y-%m-%d})")
    elif now < cert.not_before:
        status = "critical"
        problems.append(f"certificate not valid until {cert.not_before:%Y-%m-%d %H:%M} UTC")
    elif days < crit_days:
        status = "critical"
        problems.append(f"expires in {days} day(s) (critical threshold {crit_days})")
    elif days < warn_days:
        status = "warning"
        problems.append(f"expires in {days} day(s) (warning threshold {warn_days})")
    if hostname is not None and not hostname_matches(hostname, cert.dns_names, cert.ip_addresses):
        status = worst(status, "critical")
        names = ", ".join(cert.dns_names + cert.ip_addresses) or "none"
        problems.append(f"hostname {hostname!r} does not match certificate names ({names})")
    return status, problems
