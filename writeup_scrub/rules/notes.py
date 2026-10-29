"""WS006 -- private-note artefacts from Obsidian and Notion.

Writeups are usually drafted in a personal vault, and the vault leaks through:
frontmatter that lists your internal status and tags, ``[[wikilinks]]`` that
only resolve inside your vault, Obsidian callout syntax that GitHub renders as
literal text, and ``%%comments%%`` that were never meant to be read.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import Document, Line
from ..findings import Finding, Severity
from .base import Rule, substitute_lines

FRONTMATTER_KEY_RE = re.compile(r"^(?P<key>[A-Za-z0-9_\-. ]+):(?P<rest>.*)$")
FRONTMATTER_CONT_RE = re.compile(r"^(?:\s+\S|\s*-\s)")

WIKILINK_RE = re.compile(
    r"(?P<embed>!)?\[\[(?P<target>[^\]\|#]*)(?:#(?P<anchor>[^\]\|]+))?"
    r"(?:\|(?P<alias>[^\]]+))?\]\]"
)

CALLOUT_RE = re.compile(
    r"^(?P<quote>\s{0,3}>+\s*)\[!(?P<type>[A-Za-z][A-Za-z\-]*)\](?P<fold>[+-]?)(?P<title>.*)$"
)

INLINE_COMMENT_RE = re.compile(r"%%(?P<body>(?!%%).*?)%%")
BLOCK_COMMENT_DELIM_RE = re.compile(r"^\s*%%\s*$")

# Obsidian callout type -> GitHub-flavoured markdown alert type.
CALLOUT_MAP = {
    "note": "NOTE",
    "info": "NOTE",
    "abstract": "NOTE",
    "summary": "NOTE",
    "tldr": "NOTE",
    "example": "NOTE",
    "quote": "NOTE",
    "cite": "NOTE",
    "tip": "TIP",
    "hint": "TIP",
    "success": "TIP",
    "check": "TIP",
    "done": "TIP",
    "important": "IMPORTANT",
    "question": "IMPORTANT",
    "help": "IMPORTANT",
    "faq": "IMPORTANT",
    "todo": "IMPORTANT",
    "warning": "WARNING",
    "attention": "WARNING",
    "caution": "CAUTION",
    "danger": "CAUTION",
    "error": "CAUTION",
    "bug": "CAUTION",
    "failure": "CAUTION",
    "fail": "CAUTION",
    "missing": "CAUTION",
}
GITHUB_ALERTS = {"NOTE", "TIP", "IMPORTANT", "WARNING", "CAUTION"}


class PrivateNoteRule(Rule):
    id = "WS006"
    severity = Severity.LOW
    title = "private-note artefacts"
    catches = (
        "configured YAML frontmatter keys, `[[wikilinks]]`, Obsidian callouts "
        "and `%%comments%%`"
    )
    preserves = (
        "frontmatter keys you did not list (`title`, `date`, ...), the visible "
        "text of every wikilink, and the callout body"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._frontmatter(doc, cfg)
        if cfg.get("strip_comments", True):
            findings += self._comments(doc)
        findings += self._wikilinks(doc, cfg)
        if cfg.get("convert_callouts", True):
            findings += self._callouts(doc)
        return findings

    # -- frontmatter -------------------------------------------------------

    def _frontmatter(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        drop_keys = {value.lower() for value in cfg.get("drop_frontmatter_keys", [])}
        span = doc.frontmatter_span()
        if span is None:
            return []
        open_idx, close_idx = span
        findings: list[Finding] = []
        body = [
            (i, doc.lines[i])
            for i in range(open_idx + 1, close_idx)
            if not doc.lines[i].dropped
        ]

        dropping: str | None = None
        for _, line in body:
            match = FRONTMATTER_KEY_RE.match(line.text)
            if match and not FRONTMATTER_CONT_RE.match(line.text):
                key = match.group("key").strip().lower()
                if key in drop_keys:
                    dropping = key
                    line.dropped = True
                    findings.append(
                        Finding(
                            rule=self.id,
                            severity=self.severity,
                            line=line.number,
                            message=f"frontmatter key '{key}' removed",
                            original=line.text,
                            replacement="",
                        )
                    )
                else:
                    dropping = None
                continue
            if dropping is not None and FRONTMATTER_CONT_RE.match(line.text):
                line.dropped = True
                continue
            dropping = None

        remaining = [
            doc.lines[i]
            for i in range(open_idx + 1, close_idx)
            if not doc.lines[i].dropped and doc.lines[i].text.strip()
        ]
        if not remaining and cfg.get("drop_empty_frontmatter", True):
            for i in range(open_idx, close_idx + 1):
                doc.lines[i].dropped = True
            findings.append(
                Finding(
                    rule=self.id,
                    severity=self.severity,
                    line=doc.lines[open_idx].number,
                    message="empty frontmatter block removed",
                    replacement="",
                )
            )
        return findings

    # -- comments ----------------------------------------------------------

    def _comments(self, doc: Document) -> list[Finding]:
        findings = substitute_lines(
            doc,
            INLINE_COMMENT_RE,
            lambda match, index, line: "",
            rule=self.id,
            severity=self.severity,
            message="private comment removed",
        )
        # A %% on its own line opens a block comment that runs to the next one.
        # An unterminated block is left alone: guessing where it ends would
        # silently delete the rest of the writeup.
        inside = False
        opener: Line | None = None
        pending: list[Line] = []
        for _, line in doc.active():
            if BLOCK_COMMENT_DELIM_RE.match(line.text):
                if inside:
                    for item in pending:
                        item.dropped = True
                    if opener is not None:
                        opener.dropped = True
                    line.dropped = True
                    findings.append(
                        Finding(
                            rule=self.id,
                            severity=self.severity,
                            line=(opener or line).number,
                            message="private comment block removed",
                            original="\n".join(item.text for item in pending),
                            replacement="",
                            extra={"lines_removed": len(pending)},
                        )
                    )
                    pending = []
                    inside = False
                    opener = None
                else:
                    inside = True
                    opener = line
                continue
            if inside:
                pending.append(line)
        return findings

    # -- wikilinks ---------------------------------------------------------

    def _wikilinks(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        mode = cfg.get("wikilink_mode", "text")
        extension = cfg.get("wikilink_extension", ".md")

        def decide(match: re.Match[str], index: int, line: Line) -> str | None:
            target = (match.group("target") or "").strip()
            alias = (match.group("alias") or "").strip()
            anchor = (match.group("anchor") or "").strip()
            label = alias or (target if target else anchor)
            if match.group("embed"):
                if mode == "link" and target:
                    return f"![{label}]({_href(target, extension, anchor)})"
                return label
            if mode == "link" and target:
                return f"[{label}]({_href(target, extension, anchor)})"
            return label

        return substitute_lines(
            doc,
            WIKILINK_RE,
            decide,
            rule=self.id,
            severity=self.severity,
            message=f"wikilink converted to {mode}",
        )

    # -- callouts ----------------------------------------------------------

    def _callouts(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        index = 0
        while index < len(doc.lines):
            line = doc.lines[index]
            if line.dropped:
                index += 1
                continue
            match = CALLOUT_RE.match(line.text)
            if not match:
                index += 1
                continue
            original = line.text
            kind = match.group("type").lower()
            alert = CALLOUT_MAP.get(kind, "NOTE")
            quote = match.group("quote")
            title = match.group("title").strip()
            line.text = f"{quote}[!{alert}]"
            if line.text == original and not title:
                index += 1  # already GitHub-flavoured; nothing to report
                continue
            offset = 0
            if title:
                doc.insert_after(index, f"{quote}**{title}**")
                offset = 1
            findings.append(
                Finding(
                    rule=self.id,
                    severity=self.severity,
                    line=line.number,
                    message=f"Obsidian callout '{kind}' normalised to GitHub [!{alert}]",
                    original=original,
                    replacement=line.text,
                )
            )
            index += 1 + offset
        return findings


def _href(target: str, extension: str, anchor: str) -> str:
    href = target
    if "." not in target.rsplit("/", 1)[-1]:
        href = target + extension
    href = href.replace(" ", "%20")
    if anchor:
        href += "#" + anchor.lower().replace(" ", "-")
    return href
