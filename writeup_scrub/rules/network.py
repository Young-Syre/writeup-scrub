"""WS005 -- the operator's own tunnel addresses.

Lab ranges are the narrative: ``10.10.11.3`` *is* the box. The author's own
``10.10.14.37`` tunnel address is not, and it links a writeup to a session.

Nothing is stripped until ``strip_cidrs`` names a range. When both a strip and
a preserve range match, the longer prefix wins, so a strip of ``10.10.14.0/24``
beats the default preserve of ``10.10.0.0/16``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..document import Document, Line
from ..findings import Finding, Severity
from .base import Rule, substitute_lines

IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")


class OperatorNetworkRule(Rule):
    id = "WS005"
    severity = Severity.HIGH
    title = "operator network details"
    catches = "IPv4 addresses inside the CIDRs you list in `strip_cidrs`"
    preserves = (
        "HTB lab ranges (10.10.0.0/16, 10.129.0.0/16), RFC1918 and loopback by "
        "default; strips nothing at all until you configure a range"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        strip = _networks(cfg.get("strip_cidrs", []), "strip_cidrs")
        if not strip:
            return []
        preserve = _networks(cfg.get("preserve_cidrs", []), "preserve_cidrs")
        marker = cfg["marker"]

        def decide(match: re.Match[str], index: int, line: Line) -> str | None:
            try:
                address = ipaddress.IPv4Address(match.group(1))
            except ipaddress.AddressValueError:
                return None
            strip_hit = _longest_match(address, strip)
            if strip_hit is None:
                return None
            preserve_hit = _longest_match(address, preserve)
            if preserve_hit is not None and preserve_hit >= strip_hit:
                return None
            return marker

        return substitute_lines(
            doc,
            IPV4_RE,
            decide,
            rule=self.id,
            severity=self.severity,
            message="operator address redacted",
        )


def _networks(values: list[str], setting: str) -> list[ipaddress.IPv4Network]:
    out = []
    for value in values:
        try:
            out.append(ipaddress.IPv4Network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"rules.WS005.{setting}: {value!r} is not a CIDR: {exc}")
    return out


def _longest_match(
    address: ipaddress.IPv4Address, networks: list[ipaddress.IPv4Network]
) -> int | None:
    """Prefix length of the most specific matching network, or ``None``."""
    best: int | None = None
    for network in networks:
        if address in network and (best is None or network.prefixlen > best):
            best = network.prefixlen
    return best
