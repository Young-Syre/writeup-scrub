"""Rule base class and shared substitution helper."""

from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from ..document import Document, Line
from ..findings import Finding, Severity

# decide(match, index, line) -> replacement string, or None to leave it alone
Decider = Callable[[re.Match[str], int, Line], str | None]


class Rule:
    """A single, independently toggleable transformation."""

    id: str = ""
    severity: Severity = Severity.INFO
    title: str = ""
    catches: str = ""
    preserves: str = ""

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError  # pragma: no cover


def substitute_lines(
    doc: Document,
    pattern: re.Pattern[str],
    decide: Decider,
    *,
    rule: str,
    severity: Severity,
    message: str,
    indices: Iterable[int] | None = None,
) -> list[Finding]:
    """Rewrite regex matches line by line, one finding per replacement.

    ``decide`` returns the replacement (or ``None`` to keep the match), which is
    where every context-sensitive judgement in this tool lives.
    """
    findings: list[Finding] = []
    targets = (
        [(i, doc.lines[i]) for i in indices if not doc.lines[i].dropped]
        if indices is not None
        else doc.active()
    )
    for index, line in targets:
        out: list[str] = []
        cursor = 0
        changed = False
        for match in pattern.finditer(line.text):
            replacement = decide(match, index, line)
            if replacement is None:
                continue
            out.append(line.text[cursor : match.start()])
            out.append(replacement)
            cursor = match.end()
            changed = True
            findings.append(
                Finding(
                    rule=rule,
                    severity=severity,
                    line=line.number,
                    message=message,
                    original=match.group(0),
                    replacement=replacement,
                )
            )
        if changed:
            out.append(line.text[cursor:])
            line.text = "".join(out)
    return findings


def keyword_pattern(words: Iterable[str]) -> re.Pattern[str]:
    """Case-insensitive alternation with word boundaries where they make sense."""
    parts = []
    for word in words:
        escaped = re.escape(word.lower())
        prefix = r"\b" if word[:1].isalnum() else ""
        suffix = r"\b" if word[-1:].isalnum() else ""
        parts.append(prefix + escaped + suffix)
    return re.compile("|".join(parts), re.IGNORECASE)
