"""WS007 -- unresolved scratch content.

This rule never rewrites anything. Deleting a half-finished thought silently is
worse than publishing it: the author would not know the section was empty. So
everything here is reported for human review.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import ATX_HEADING_RE, Document
from ..findings import Finding, Severity
from .base import Rule


class ScratchContentRule(Rule):
    id = "WS007"
    severity = Severity.INFO
    title = "unresolved scratch content"
    catches = (
        "TODO/FIXME/XXX/HACK markers, hint-seeking asides "
        "(\"ask in discord\", \"got hint from\"), and headings with no content"
    )
    preserves = "everything -- this rule only warns, it never edits"

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        markers = [value for value in cfg.get("markers", []) if value]
        phrases = [value.lower() for value in cfg.get("phrases", []) if value]
        marker_re = (
            re.compile(r"\b(" + "|".join(re.escape(m) for m in markers) + r")\b")
            if markers
            else None
        )

        for _, line in doc.active():
            if marker_re is not None:
                found = marker_re.search(line.text)
                if found:
                    findings.append(
                        Finding(
                            rule=self.id,
                            severity=self.severity,
                            line=line.number,
                            kind="warning",
                            message=f"scratch marker '{found.group(1)}' left in the text",
                        )
                    )
            lowered = line.text.lower()
            for phrase in phrases:
                if phrase in lowered:
                    findings.append(
                        Finding(
                            rule=self.id,
                            severity=self.severity,
                            line=line.number,
                            kind="warning",
                            message=f"private aside left in the text: {phrase!r}",
                        )
                    )
                    break

        if cfg.get("warn_empty_sections", True):
            findings += self._empty_sections(doc)
        return findings

    def _empty_sections(self, doc: Document) -> list[Finding]:
        """A heading with no body before the next heading of the same or higher level."""
        findings: list[Finding] = []
        headings: list[tuple[int, int, str]] = []  # (index, level, text)
        for index, line in doc.active():
            if doc.in_fence(index):
                continue
            match = ATX_HEADING_RE.match(line.text)
            if match:
                headings.append((index, len(match.group("hashes")), line.text.strip()))

        active_indices = [index for index, _ in doc.active()]
        for position, (index, level, text) in enumerate(headings):
            stop = len(doc.lines)
            for next_index, next_level, _ in headings[position + 1 :]:
                if next_level <= level:
                    stop = next_index
                    break
            else:
                stop = len(doc.lines)
            has_body = any(
                doc.lines[i].text.strip()
                for i in active_indices
                if index < i < stop and not ATX_HEADING_RE.match(doc.lines[i].text)
            )
            if not has_body:
                findings.append(
                    Finding(
                        rule=self.id,
                        severity=self.severity,
                        line=doc.lines[index].number,
                        kind="warning",
                        message=f"section has no content: {text!r}",
                    )
                )
        return findings
