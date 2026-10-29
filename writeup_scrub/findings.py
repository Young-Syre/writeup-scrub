"""Findings: the unit of reporting.

Every rule reports what it changed (``kind="redaction"``) or what a human should
look at (``kind="warning"``) as a :class:`Finding`. Findings carry the original
line number from the input file so that a report stays useful even when a rule
removed lines.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Most severe first. Used for threshold comparisons and for sorting output.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def severity_rank(severity: Severity) -> int:
    """Lower is more severe."""
    return SEVERITY_ORDER.index(severity)


def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    """True when ``severity`` is at least as severe as ``threshold``."""
    return severity_rank(severity) <= severity_rank(threshold)


def fingerprint(value: str) -> str:
    """A stable, non-reversible identifier for a redacted string.

    The JSON manifest records fingerprints rather than plaintext by default, so
    that the audit trail of "what was removed" is not itself a leak. Pass
    ``--report-reveal`` to include plaintext instead.
    """
    digest = hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()
    return f"sha256:{digest[:16]}"


def elide(value: str, keep: int = 4, limit: int = 160) -> str:
    """A short, non-sensitive hint at what a redacted string looked like."""
    collapsed = " ".join(value.split())
    if len(collapsed) <= keep:
        return "*" * len(collapsed)
    if len(collapsed) > limit:
        collapsed = collapsed[:limit] + "..."
    return collapsed[:keep] + "*" * min(8, max(1, len(collapsed) - keep))


@dataclass
class Finding:
    """One thing a rule changed, or one thing it wants a human to look at."""

    rule: str
    severity: Severity
    line: int
    message: str
    kind: str = "redaction"  # redaction | warning | hygiene
    original: str | None = None
    replacement: str | None = None
    path: str | None = None
    context: str | None = None  # the resulting line, filled in by the pipeline
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_redaction(self) -> bool:
        return self.kind == "redaction"

    def to_dict(self, *, reveal: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule": self.rule,
            "severity": self.severity.value,
            "kind": self.kind,
            "line": self.line,
            "message": self.message,
        }
        if self.path is not None:
            out["file"] = self.path
        if self.original is not None:
            if reveal:
                out["original"] = self.original
            else:
                out["original_fingerprint"] = fingerprint(self.original)
                out["original_preview"] = elide(self.original)
                out["original_length"] = len(self.original)
        if self.replacement is not None:
            out["replacement"] = self.replacement
        if self.context is not None:
            out["result_line"] = self.context
        if self.extra:
            out["details"] = dict(self.extra)
        return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.line, severity_rank(f.severity), f.rule))
