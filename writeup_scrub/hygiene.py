"""Markdown hygiene: make notes look like a published document.

None of this is about leaks; it is about a writeup that renders correctly on
GitHub. Every change is reported with an ``MD-*`` id at INFO severity, so the
publication gate never fails on cosmetics.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .document import ATX_HEADING_RE, Document
from .findings import Finding, Severity

# (language, pattern, weight) -- highest total score wins, ties by this order.
LANGUAGE_SIGNALS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("http", re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /\S*\s+HTTP/\d"), 5),
    ("http", re.compile(r"^HTTP/\d(?:\.\d)? \d{3}"), 5),
    ("http", re.compile(r"^(?:Host|User-Agent|Content-Type|Cookie|Authorization):\s"), 2),
    ("sql", re.compile(r"(?i)\b(?:select\s+.+\s+from|union\s+(?:all\s+)?select|insert\s+into|update\s+\S+\s+set|drop\s+table)\b"), 4),
    ("powershell", re.compile(r"^(?:PS )?[A-Z]:\\[^>]*>"), 5),
    ("powershell", re.compile(r"\b(?:Get|Set|New|Invoke|Import|Export|Add|Remove|Enable)-[A-Z][A-Za-z]+"), 3),
    ("powershell", re.compile(r"\$env:|\[System\.|-ExecutionPolicy|\bIEX\b"), 3),
    ("python", re.compile(r"^\s*(?:from \S+ import |import \S+$|def \w+\(|class \w+[:(])"), 4),
    ("python", re.compile(r"^\s*(?:print\(|if __name__ == )"), 3),
    ("bash", re.compile(r"^\s*(?:\$|#) \S"), 3),
    ("bash", re.compile(r"^#!/(?:usr/)?bin/(?:ba|z|s)?sh"), 5),
    ("bash", re.compile(r"^\s*(?:sudo |nmap |curl |wget |ssh |scp |cat |ls |cd |grep |chmod |chown |netstat |ss |ps |python3? |nc |smbclient |crackmapexec|nxc |impacket-|evil-winrm|hashcat |john |ffuf |gobuster|feroxbuster|dig |nslookup|ping |sqlmap)"), 3),
    ("bash", re.compile(r"\b(?:\|\s*(?:grep|awk|sed|sort|uniq|tee|xargs)\b|2>&1|&&\s)"), 2),
)

LANGUAGE_PRIORITY = ("http", "json", "sql", "powershell", "python", "bash")


class Hygiene:
    """Applies the markdown hygiene pass to a document in place."""

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        if cfg.get("close_unterminated_fences", True):
            findings += self._close_fences(doc)
        if cfg.get("infer_fence_language", True):
            findings += self._infer_languages(doc, cfg)
        if cfg.get("normalise_headings", True):
            findings += self._normalise_headings(doc)
        if cfg.get("strip_trailing_whitespace", True):
            findings += self._strip_trailing_whitespace(doc)
        limit = int(cfg.get("max_consecutive_blank_lines", 1))
        if limit > 0:
            findings += self._collapse_blanks(doc, limit)
        return findings

    # -- fences ------------------------------------------------------------

    def _close_fences(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        for fence in doc.fences():
            if fence.terminated:
                continue
            opener = doc.lines[fence.open_idx]
            closer = " " * fence.indent + fence.marker
            doc.append(closer)
            findings.append(
                Finding(
                    rule="MD-FENCE",
                    severity=Severity.INFO,
                    kind="hygiene",
                    line=opener.number,
                    message="unterminated code fence closed at end of file",
                    replacement=closer,
                )
            )
        return findings

    def _infer_languages(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        fallback = cfg.get("default_fence_language", "text")
        for fence in doc.fences():
            if fence.info.strip():
                continue
            body = [line.text for _, line in doc.fence_body(fence)]
            if not any(text.strip() for text in body):
                continue
            language = sniff_language(body) or fallback
            if not language:
                continue
            opener = doc.lines[fence.open_idx]
            opener.text = " " * fence.indent + fence.marker + language
            findings.append(
                Finding(
                    rule="MD-LANG",
                    severity=Severity.INFO,
                    kind="hygiene",
                    line=opener.number,
                    message=f"fence language inferred as '{language}'",
                    replacement=opener.text,
                )
            )
        return findings

    # -- headings ----------------------------------------------------------

    def _normalise_headings(self, doc: Document) -> list[Finding]:
        """Shift headings so the document has exactly one H1."""
        headings = [
            (index, len(match.group("hashes")))
            for index, line in doc.active()
            if not doc.in_fence(index)
            and (match := ATX_HEADING_RE.match(line.text)) is not None
        ]
        if not headings:
            return []
        findings: list[Finding] = []
        shift = min(level for _, level in headings) - 1
        seen_h1 = False
        for index, level in headings:
            new_level = level - shift
            if new_level == 1:
                if seen_h1:
                    new_level = 2
                else:
                    seen_h1 = True
            new_level = max(1, min(6, new_level))
            if new_level == level:
                continue
            line = doc.lines[index]
            match = ATX_HEADING_RE.match(line.text)
            assert match is not None
            original = line.text
            line.text = (
                match.group("indent") + "#" * new_level + match.group("rest")
            )
            findings.append(
                Finding(
                    rule="MD-HEADING",
                    severity=Severity.INFO,
                    kind="hygiene",
                    line=line.number,
                    message=f"heading level normalised H{level} -> H{new_level}",
                    replacement=line.text.strip(),
                    extra={"before": original.strip()},
                )
            )
        return findings

    # -- whitespace --------------------------------------------------------

    def _strip_trailing_whitespace(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        for index, line in doc.active():
            if doc.in_fence(index):
                continue  # code content is left byte for byte
            stripped = line.text.rstrip()
            if stripped != line.text:
                line.text = stripped
                findings.append(
                    Finding(
                        rule="MD-WS",
                        severity=Severity.INFO,
                        kind="hygiene",
                        line=line.number,
                        message="trailing whitespace stripped",
                    )
                )
        return findings

    def _collapse_blanks(self, doc: Document, limit: int) -> list[Finding]:
        findings: list[Finding] = []
        run = 0
        for index, line in doc.active():
            if doc.in_fence(index):
                run = 0
                continue
            if line.text.strip() == "":
                run += 1
                if run > limit:
                    line.dropped = True
                    findings.append(
                        Finding(
                            rule="MD-BLANK",
                            severity=Severity.INFO,
                            kind="hygiene",
                            line=line.number,
                            message="extra blank line collapsed",
                        )
                    )
            else:
                run = 0
        return findings


def sniff_language(body: list[str]) -> str | None:
    """Guess the language of a fenced block from its content."""
    text = "\n".join(body).strip()
    if not text:
        return None
    if text[0] in "{[":
        try:
            json.loads(text)
            return "json"
        except ValueError:
            pass
    scores: dict[str, int] = {}
    for language, pattern, weight in LANGUAGE_SIGNALS:
        hits = sum(1 for line in body if pattern.search(line))
        if hits:
            scores[language] = scores.get(language, 0) + weight * min(hits, 3)
    if not scores:
        return None
    best = max(scores.values())
    for language in LANGUAGE_PRIORITY:
        if scores.get(language) == best:
            return language
    return None  # pragma: no cover
