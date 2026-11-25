"""Live TLS handshakes."""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import certinfo
from .certinfo import CertInfo, worst

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class Handshake:
    der: bytes
    version: str | None
    cipher: tuple | None  # (name, protocol, secret bits)
    verified: bool | None  # None when verification was not attempted
    verify_error: str | None = None


def _handshake(host: str, port: int, timeout: float, servername: str | None, context: ssl.SSLContext):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=servername or host) as tls:
            return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()


def default_connector(host: str, port: int, timeout: float, servername: str | None, verify: bool) -> Handshake:
    """Connect, trying a verifying handshake first, then an unverified one so the
    certificate can still be reported when the chain is not trusted."""
    error = None
    if verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # hostname is checked separately so mismatches are reported, not fatal
        try:
            der, version, cipher = _handshake(host, port, timeout, servername, ctx)
            return Handshake(der, version, cipher, True)
        except ssl.SSLCertVerificationError as exc:
            error = exc.verify_message or str(exc)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass
    der, version, cipher = _handshake(host, port, timeout, servername, ctx)
    return Handshake(der, version, cipher, False if verify else None, error)


@dataclass
class HostResult:
    host: str
    port: int
    status: str
    problems: list[str] = field(default_factory=list)
    cert: CertInfo | None = None
    handshake: Handshake | None = None
    hostname_ok: bool | None = None
    error: str | None = None

    @property
    def target(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    def to_dict(self, now=None) -> dict:
        data = {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "problems": self.problems,
            "error": self.error,
            "hostname_match": self.hostname_ok,
        }
        if self.handshake is not None:
            name, _, bits = self.handshake.cipher or (None, None, None)
            data["tls"] = {"version": self.handshake.version, "cipher": name, "bits": bits,
                           "verified": self.handshake.verified, "verify_error": self.handshake.verify_error}
        if self.cert is not None:
            data["days_left"] = self.cert.days_left(now)
            data["certificate"] = self.cert.to_dict(now)
        return data


def check_host(host: str, port: int = 443, timeout: float = 10.0, servername: str | None = None,
               verify: bool = True, warn_days: int = 30, crit_days: int = 7, connector=None,
               now=None) -> HostResult:
    connector = connector or default_connector
    try:
        hs = connector(host, port, timeout, servername, verify)
    except (OSError, ssl.SSLError) as exc:
        msg = getattr(exc, "strerror", None) or str(exc) or exc.__class__.__name__
        if isinstance(exc, socket.timeout) or isinstance(exc, TimeoutError):
            msg = f"timed out after {timeout:g}s"
        return HostResult(host, port, "error", [f"connection failed: {msg}"], error=msg)
    if not hs.der:
        return HostResult(host, port, "error", ["server sent no certificate"], handshake=hs, error="no certificate")
    try:
        cert = certinfo.decode_der(hs.der)
    except ValueError as exc:
        return HostResult(host, port, "error", [str(exc)], handshake=hs, error=str(exc))
    name = servername or host
    status, problems = certinfo.evaluate(cert, now=now, warn_days=warn_days, crit_days=crit_days, hostname=name)
    hostname_ok = certinfo.hostname_matches(name, cert.dns_names, cert.ip_addresses)
    if hs.verified is False:
        status = worst(status, "critical")
        problems.append(f"certificate chain not trusted: {hs.verify_error or 'verification failed'}")
    if hs.version in DEPRECATED_PROTOCOLS:
        status = worst(status, "warning")
        problems.append(f"server negotiated deprecated protocol {hs.version}")
    if hs.cipher and hs.cipher[2] is not None and hs.cipher[2] < 128:
        status = worst(status, "warning")
        problems.append(f"weak cipher {hs.cipher[0]} ({hs.cipher[2]} bits)")
    return HostResult(host, port, status, problems, cert, hs, hostname_ok)


def check_many(targets, workers: int = 8, **kwargs) -> list[HostResult]:
    """Check targets concurrently; results keep the input order."""
    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        futures = [pool.submit(check_host, host, port, **kwargs) for host, port in targets]
        return [f.result() for f in futures]
