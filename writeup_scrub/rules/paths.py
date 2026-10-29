"""WS003 -- the operator's own home directory layout.

``/home/jordan/htb/blackfield/loot`` tells the reader where the author keeps
their files and what their username is. ``/home/operator/htb/blackfield/loot``
tells the reader exactly as much as they need about the technique.

The trailing path is always preserved. The ``users`` setting matters: with an
empty list the rule rewrites *every* home directory, including a target
machine's ``/home/svc_sql``, so a writeup repository usually wants
``users = ["yourname"]``.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import Document, Line
from ..findings import Finding, Severity
from .base import Rule, substitute_lines

USERNAME = r"[A-Za-z0-9](?:[A-Za-z0-9._\- ]{0,30}[A-Za-z0-9])?"

POSIX_HOME_RE = re.compile(rf"(?P<root>/home/)(?P<user>{USERNAME})(?=$|[/\s'\"`:,;)\]}}])")
MAC_HOME_RE = re.compile(rf"(?P<root>/Users/)(?P<user>{USERNAME})(?=$|[/\s'\"`:,;)\]}}])")
WIN_HOME_RE = re.compile(
    rf"(?P<root>[Cc]:\\\\?Users\\\\?)(?P<user>{USERNAME})(?=$|[\\/\s'\"`:,;)\]}}])"
)
WIN_FWD_HOME_RE = re.compile(
    rf"(?P<root>[Cc]:/Users/)(?P<user>{USERNAME})(?=$|[/\s'\"`:,;)\]}}])"
)


class LocalPathRule(Rule):
    id = "WS003"
    severity = Severity.MEDIUM
    title = "local paths"
    catches = "`/home/<user>`, `/Users/<user>` and `C:\\Users\\<user>` prefixes"
    preserves = (
        "the whole trailing path, and any username in `preserve_users` "
        "(Windows `Public`/`Default`/`Administrator` are target-side by default)"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        placeholder = cfg["placeholder"]
        only = {value.lower() for value in cfg.get("users", [])}
        preserve = {value.lower() for value in cfg.get("preserve_users", [])}
        preserve.add(placeholder.lower())

        def decide(match: re.Match[str], index: int, line: Line) -> str | None:
            user = match.group("user")
            if user.lower() in preserve:
                return None
            if only and user.lower() not in only:
                return None
            return match.group("root") + placeholder

        findings: list[Finding] = []
        for pattern in (POSIX_HOME_RE, MAC_HOME_RE, WIN_HOME_RE, WIN_FWD_HOME_RE):
            findings += substitute_lines(
                doc,
                pattern,
                decide,
                rule=self.id,
                severity=self.severity,
                message="operator home directory rewritten",
            )
        return findings
