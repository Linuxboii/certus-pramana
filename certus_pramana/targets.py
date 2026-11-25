"""Parsing of host targets ('host', 'host:port', 'https://host/...', '[v6]:port')."""

from __future__ import annotations

import urllib.parse

DEFAULT_PORT = 443
SCHEME_PORTS = {"https": 443, "ldaps": 636, "imaps": 993, "pop3s": 995, "smtps": 465, "ftps": 990}


def _port(value: str, original: str) -> int:
    if not value.isdigit() or not 0 < int(value) < 65536:
        raise ValueError(f"invalid port in target {original!r}")
    return int(value)


def parse_target(text: str, default_port: int = DEFAULT_PORT) -> tuple[str, int]:
    original = text
    text = text.strip()
    if not text:
        raise ValueError("empty target")
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        if not parsed.hostname:
            raise ValueError(f"no host in {original!r}")
        try:
            port = parsed.port
        except ValueError:
            raise ValueError(f"invalid port in target {original!r}") from None
        return parsed.hostname, port or SCHEME_PORTS.get(parsed.scheme.lower(), default_port)
    parts = text.split()
    if len(parts) == 2:
        return parts[0].strip("[]"), _port(parts[1], original)
    if len(parts) > 2:
        raise ValueError(f"cannot parse target {original!r}")
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            return host, _port(rest[1:], original)
        if rest:
            raise ValueError(f"cannot parse target {original!r}")
        return host, default_port
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, _port(port, original)
    return text, default_port  # bare hostname or bare IPv6 address


def parse_targets_file(path: str, default_port: int = DEFAULT_PORT) -> list[tuple[str, int]]:
    """One target per line; blank lines and ``#`` comments are ignored."""
    targets = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                targets.append(parse_target(line, default_port))
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from None
    return targets
