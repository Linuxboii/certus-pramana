"""Command-line interface for certus-pramana."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, certinfo, probe
from .certinfo import STATUS_RANK, CertInfo, format_name
from .colors import Painter, should_color
from .targets import parse_target, parse_targets_file

STATUS_STYLE = {"ok": ("OK", "green"), "warning": ("WARN", "yellow"), "critical": ("CRIT", "red"),
                "expired": ("EXPIRED", "red"), "error": ("ERROR", "magenta")}
EXIT_FOR = {"ok": 0, "warning": 1, "critical": 2, "expired": 2, "error": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="certus-pramana",
        description="Check TLS certificates of live hosts or local PEM files: expiry, names, issuer, "
                    "protocol and cipher. Exit status 0 ok, 1 warning, 2 critical/expired/error. "
                    "Only scan systems you own or are authorized to test.",
    )
    p.add_argument("targets", nargs="*", metavar="HOST[:PORT]",
                   help="hosts to check (host, host:port, [v6]:port or https:// URL); default localhost:443")
    p.add_argument("-f", "--file", metavar="PATH", help="read targets from a file, one per line (# comments)")
    p.add_argument("--pem", action="append", default=[], metavar="FILE",
                   help="inspect a local PEM certificate or bundle instead of connecting (repeatable)")
    p.add_argument("--hostname", help="with --pem: also check that the certificate matches this name")
    p.add_argument("-w", "--warn-days", type=int, default=30, help="warn when fewer days remain (default 30)")
    p.add_argument("-c", "--crit-days", type=int, default=7, help="critical when fewer days remain (default 7)")
    p.add_argument("--timeout", type=float, default=10.0, help="connection timeout in seconds (default 10)")
    p.add_argument("--servername", help="SNI name to send (default: the target host)")
    p.add_argument("--no-verify", action="store_true",
                   help="do not verify the chain against the system trust store")
    p.add_argument("--workers", type=int, default=8, help="parallel connections in batch mode (default 8)")
    p.add_argument("-v", "--verbose", action="store_true", help="full details even in batch mode")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _badge(status: str, paint: Painter) -> str:
    label, color = STATUS_STYLE[status]
    return paint(f"{label:<7}", "bold", color)


def _cert_lines(cert: CertInfo, paint: Painter) -> list[str]:
    now = certinfo.utcnow()
    days = cert.days_left(now)
    rows = [
        ("Subject", format_name(cert.subject)),
        ("Issuer", format_name(cert.issuer) + ("  (self-signed)" if cert.self_signed else "")),
        ("SANs", ", ".join(cert.dns_names + cert.ip_addresses) or "(none)"),
        ("Valid", f"{cert.not_before:%Y-%m-%d %H:%M} -> {cert.not_after:%Y-%m-%d %H:%M} UTC"),
        ("Expires", f"in {days} day(s)" if days >= 0 else f"{-days} day(s) ago"),
        ("Serial", cert.serial),
        ("SHA-256", cert.sha256),
    ]
    if cert.ocsp:
        rows.append(("OCSP", ", ".join(cert.ocsp)))
    if cert.ca_issuers:
        rows.append(("CA issuers", ", ".join(cert.ca_issuers)))
    if cert.crl:
        rows.append(("CRL", ", ".join(cert.crl)))
    return [f"  {paint(k.ljust(10), 'cyan')}  {v}" for k, v in rows]


def render_host(r: probe.HostResult, paint: Painter, detailed: bool) -> list[str]:
    summary = r.problems[0] if r.problems else (
        f"expires in {r.cert.days_left()} day(s) ({r.cert.not_after:%Y-%m-%d})" if r.cert else "")
    lines = [f"{_badge(r.status, paint)} {paint(r.target, 'bold')}  {summary}"]
    if not detailed:
        lines += [f"        - {p}" for p in r.problems[1:]]
        return lines
    if r.cert is not None:
        lines += _cert_lines(r.cert, paint)
    if r.handshake is not None:
        hs = r.handshake
        if hs.cipher:
            lines.append(f"  {paint('Protocol'.ljust(10), 'cyan')}  {hs.version}  {hs.cipher[0]} ({hs.cipher[2]} bits)")
        trust = {True: paint("trusted", "green"), False: paint(f"NOT trusted ({hs.verify_error})", "red"),
                 None: "not verified (--no-verify)"}[hs.verified]
        lines.append(f"  {paint('Chain'.ljust(10), 'cyan')}  {trust}")
    if r.hostname_ok is not None:
        lines.append(f"  {paint('Hostname'.ljust(10), 'cyan')}  "
                     + (paint("matches", "green") if r.hostname_ok else paint("MISMATCH", "red")))
    for p in r.problems:
        lines.append(f"  {paint('!', 'bold', 'red' if STATUS_RANK[r.status] >= 2 else 'yellow')} {p}")
    return lines


def run_pem(args, paint: Painter) -> int:
    results = []
    for path in args.pem:
        for index, cert in enumerate(certinfo.load_pem_file(path)):
            status, problems = certinfo.evaluate(cert, warn_days=args.warn_days, crit_days=args.crit_days,
                                                 hostname=args.hostname if index == 0 else None)
            results.append((path, index, cert, status, problems))
    if args.json:
        print(json.dumps({"results": [
            {"source": path, "index": i, "status": s, "problems": pr, "days_left": c.days_left(),
             "certificate": c.to_dict()} for path, i, c, s, pr in results]}, indent=2))
    else:
        blocks = []
        for path, index, cert, status, problems in results:
            head = f"{_badge(status, paint)} {paint(f'{path} #{index}', 'bold')}  {cert.common_name or format_name(cert.subject)}"
            block = [head] + _cert_lines(cert, paint)
            block += [f"  {paint('!', 'bold', 'yellow')} {p}" for p in problems]
            blocks.append("\n".join(block))
        print("\n\n".join(blocks))
    return max((EXIT_FOR[status] for *_, status, _ in results), default=0)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paint = Painter(should_color(sys.stdout) and not args.no_color)
    if args.crit_days > args.warn_days:
        print("certus-pramana: error: --crit-days must not exceed --warn-days", file=sys.stderr)
        return 2
    try:
        if args.pem:
            return run_pem(args, paint)
        targets = [parse_target(t) for t in args.targets]
        if args.file:
            targets += parse_targets_file(args.file)
    except (OSError, ValueError) as exc:
        print(f"certus-pramana: error: {exc}", file=sys.stderr)
        return 2
    if not targets:
        targets = [("localhost", 443)]

    results = probe.check_many(targets, workers=args.workers, timeout=args.timeout, servername=args.servername,
                               verify=not args.no_verify, warn_days=args.warn_days, crit_days=args.crit_days)
    if args.json:
        print(json.dumps({"results": [r.to_dict() for r in results]}, indent=2))
    else:
        detailed = args.verbose or len(results) == 1
        out = []
        for r in results:
            out.append("\n".join(render_host(r, paint, detailed)))
        print(("\n\n" if detailed else "\n").join(out))
        if len(results) > 1:
            counts = {}
            for r in results:
                counts[r.status] = counts.get(r.status, 0) + 1
            summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda kv: STATUS_RANK[kv[0]]))
            print(f"\n{len(results)} target(s): {summary}")
    return max(EXIT_FOR[r.status] for r in results)
