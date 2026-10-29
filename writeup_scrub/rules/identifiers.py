"""WS004 -- personal identifiers, minus the in-universe ones.

``admin@target.htb`` is part of the machine. ``a.reporter@gmail.com`` is
not. The two are told apart by domain, and both lists are configurable:
``preserve_domains`` for target/lab domains and ``preserve_addresses`` for an
address the author wants kept, such as a public contact address.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import Document, Line
from ..findings import Finding, Severity
from .base import Rule, substitute_lines

# A domain needs at least one dot and an alphabetic final label, so neither
# `svc@10.10.10.192` (impacket's domain/user@host) nor the `user@target` comment
# at the end of an SSH public key is treated as an email address.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"(?P<local>[A-Za-z0-9._%+\-]+)@"
    r"(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,})"
    r"(?![A-Za-z0-9\-])"
)

# Deliberately narrow. Either a parenthesised area code, or a 3-3-4 grouping
# whose two separators match (so "100.200 3000" is not a phone number). The
# lookarounds keep it away from IPv4 addresses, ports and version strings.
PHONE_RE = re.compile(
    r"(?<![\d.\-/:])"
    r"(?:"
    r"\(\d{3}\)[ .\-]?\d{3}[ .\-]?\d{4}"
    r"|\d{3}(?P<sep>[.\-])\d{3}(?P=sep)\d{4}"
    r")"
    r"(?![\d\-/])"
)
INTL_PHONE_RE = re.compile(
    r"(?<![\d.\-/:\w])\+\d{1,3}[ .\-]?\d{2,4}[ .\-]?\d{2,4}[ .\-]?\d{2,4}(?![\d\-/])"
)


class IdentifierRule(Rule):
    id = "WS004"
    severity = Severity.MEDIUM
    title = "personal identifiers"
    catches = "email addresses and phone numbers belonging to the author"
    preserves = (
        "in-universe addresses on target/lab domains (`admin@target.htb`, "
        "`*.local`, `example.com`) and anything in `preserve_addresses`"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if cfg.get("detect_emails", True):
            findings += self._emails(doc, cfg)
        if cfg.get("detect_phones", True):
            for pattern in (PHONE_RE, INTL_PHONE_RE):
                findings += substitute_lines(
                    doc,
                    pattern,
                    lambda match, index, line: cfg["phone_marker"],
                    rule=self.id,
                    severity=self.severity,
                    message="phone number redacted",
                )
        return findings

    def _emails(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        keep_addresses = {value.lower() for value in cfg.get("preserve_addresses", [])}
        keep_domains = [value.lower().lstrip(".") for value in cfg.get("preserve_domains", [])]

        def decide(match: re.Match[str], index: int, line: Line) -> str | None:
            address = match.group(0).lower()
            domain = match.group("domain").lower()
            if address in keep_addresses:
                return None
            if _domain_matches(domain, keep_domains):
                return None
            return cfg["email_marker"]

        return substitute_lines(
            doc,
            EMAIL_RE,
            decide,
            rule=self.id,
            severity=self.severity,
            message="email address redacted",
        )


def _domain_matches(domain: str, allowed: list[str]) -> bool:
    """``htb`` matches ``target.htb``; ``example.com`` matches ``mail.example.com``."""
    for candidate in allowed:
        if domain == candidate or domain.endswith("." + candidate):
            return True
    return False
