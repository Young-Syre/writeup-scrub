"""WS002 -- live credentials pasted into command output.

Prefix-shaped detections only. A token that looks like nothing in this table
will not be caught, which is why the README says a human still reads the diff.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import FENCE_RE, Document, Line
from ..findings import Finding, Severity
from .base import Rule, substitute_lines

# name -> (pattern, human description)
PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "aws_access_key": (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS access key id",
    ),
    "google_api_key": (
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "Google API key",
    ),
    "stripe_live_key": (
        re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{10,}\b"),
        "Stripe live secret key",
    ),
    "github_token": (
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        "GitHub token",
    ),
    "github_pat": (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "GitHub fine-grained PAT",
    ),
    "slack_token": (
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
        "Slack token",
    ),
    "sendgrid_key": (
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
        "SendGrid API key",
    ),
    "openai_key": (
        # No need to spell out proj-/svcacct-/admin-: the character class
        # already contains the hyphen, so the prefixes match as body.
        re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
        "OpenAI API key",
    ),
    "twilio_key": (
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "Twilio API key SID",
    ),
    "jwt": (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "JWT",
    ),
}

JWT_PATTERNS = {"jwt"}

SESSION_COOKIE_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "session_cookie": (
        re.compile(
            # Longest first: `session` before `sessionid` only matched the
            # latter by backtracking off the `=`.
            r"\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session|"
            r"connect\.sid|_session_id|sessionid|session|remember_token)"
            r"=([A-Za-z0-9%._\-]{8,})"
        ),
        "session cookie",
    ),
    "bearer_header": (
        re.compile(r"(?i)\bAuthorization:\s*(?:Bearer|Token)\s+([A-Za-z0-9._\-]{12,})"),
        "Authorization header",
    ),
}

PRIVATE_KEY_BEGIN = re.compile(
    r"^(?P<indent>\s*)-----BEGIN (?P<kind>[A-Z0-9 ]*?)PRIVATE KEY(?: BLOCK)?-----\s*$"
)
PRIVATE_KEY_END = re.compile(r"^\s*-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----\s*$")

# A PEM payload is base64, conventionally 64 characters to the line, optionally
# preceded by RFC 1421 headers (``Proc-Type:``, ``DEK-Info:``) and the blank
# line that separates those from the payload. The scan for the body needs these
# because a writeup quite reasonably contains a BEGIN banner with no END banner
# -- someone pasted the first line to show the key was unencrypted, or truncated
# the block by hand. Without a shape test the forward scan treats the rest of
# the file as key material and deletes it.
PEM_BASE64_RE = re.compile(r"^\s*[A-Za-z0-9+/]+={0,2}\s*$")
PEM_HEADER_RE = re.compile(r"^\s*[A-Za-z][A-Za-z0-9-]*:\s*\S")

# A base64 line this short is more likely to be an ordinary word on its own
# line than a key. It is only required of the *first* body line: the last line
# of a real payload is as short as the key length leaves it.
PEM_MIN_FIRST_LINE = 16


class SecretsRule(Rule):
    id = "WS002"
    severity = Severity.CRITICAL
    title = "live secrets"
    catches = (
        "AWS (AKIA/ASIA), Google AIza, Stripe sk_live/rk_live, GitHub "
        "ghp_/gho_/ghu_/ghs_/github_pat_, Slack xox[baprs]-, SendGrid SG., "
        "OpenAI sk-, Twilio SK, JWTs, and PEM private-key bodies"
    )
    preserves = (
        "the surrounding command and the BEGIN/END key banners, so the reader "
        "still sees that a key was there; target session cookies unless "
        "`detect_session_cookies` is turned on"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        marker = cfg["marker"]
        disabled = set(cfg.get("disabled_patterns", []))
        findings: list[Finding] = []

        active: dict[str, tuple[re.Pattern[str], str]] = {
            name: value for name, value in PATTERNS.items() if name not in disabled
        }
        if not cfg.get("detect_jwts", True):
            for name in JWT_PATTERNS:
                active.pop(name, None)
        if cfg.get("detect_session_cookies", False):
            for name, value in SESSION_COOKIE_PATTERNS.items():
                if name not in disabled:
                    active[name] = value

        for name, (pattern, description) in active.items():
            findings += substitute_lines(
                doc,
                pattern,
                _replacer(name, marker),
                rule=self.id,
                severity=self.severity,
                message=f"{description} redacted",
            )

        if cfg.get("detect_private_keys", True):
            findings += self._redact_private_keys(doc, cfg)
        return findings

    def _redact_private_keys(
        self, doc: Document, cfg: dict[str, Any]
    ) -> list[Finding]:
        """Replace the body of a PEM private key, keeping the BEGIN/END banners."""
        marker = cfg["private_key_marker"]
        findings: list[Finding] = []
        index = 0
        while index < len(doc.lines):
            line = doc.lines[index]
            if line.dropped:
                index += 1
                continue
            begin = PRIVATE_KEY_BEGIN.match(line.text)
            if not begin:
                index += 1
                continue
            body: list[Line] = []
            # Blank lines are only part of the block if more body follows them,
            # so they are held back rather than committed on sight.
            pending: list[Line] = []
            cursor = index + 1
            end_found = False
            stopped_at: Line | None = None
            while cursor < len(doc.lines):
                candidate = doc.lines[cursor]
                if candidate.dropped:
                    cursor += 1
                    continue
                text = candidate.text
                if PRIVATE_KEY_END.match(text):
                    end_found = True
                    break
                if FENCE_RE.match(text):
                    break  # key block ran past the end of its code fence
                if not text.strip():
                    pending.append(candidate)
                    cursor += 1
                    continue
                if PEM_HEADER_RE.match(text) or (
                    PEM_BASE64_RE.match(text)
                    and (body or len(text.strip()) >= PEM_MIN_FIRST_LINE)
                ):
                    body.extend(pending)
                    pending.clear()
                    body.append(candidate)
                    cursor += 1
                    continue
                # Prose. The block has no END banner and stops here, not at the
                # end of the file.
                stopped_at = candidate
                break
            if body:
                removed = "\n".join(item.text for item in body)
                for item in body:
                    item.dropped = True
                first = body[0]
                doc.insert_after(index, begin.group("indent") + marker)
                findings.append(
                    Finding(
                        rule=self.id,
                        severity=self.severity,
                        line=first.number,
                        message=(
                            "private key body redacted"
                            + ("" if end_found else " (no END banner found)")
                        ),
                        original=removed,
                        replacement=marker,
                        extra={"lines_removed": len(body)},
                    )
                )
            elif not end_found:
                # A banner with nothing key-shaped after it. Redacting here
                # would mean deleting the writeup, so say so and change nothing.
                findings.append(
                    Finding(
                        rule=self.id,
                        severity=Severity.MEDIUM,
                        line=line.number,
                        kind="warning",
                        message=(
                            "private key banner with no key body and no END "
                            "banner; nothing redacted -- check by hand that no "
                            "key material follows"
                        ),
                        extra={
                            "stopped_at_line": (
                                stopped_at.number if stopped_at else None
                            )
                        },
                    )
                )
            # A line that stopped the scan has not been consumed: it could be
            # the next BEGIN banner.
            index = cursor if stopped_at is not None else cursor + 1
        return findings


def _replacer(name: str, marker: str):
    def decide(match: re.Match[str], index: int, line: Line) -> str | None:
        # Patterns with a capture group redact only the secret part, keeping the
        # header or cookie name so the reader still sees what was there.
        if match.re.groups and match.group(1) is not None:
            start, end = match.span(1)
            whole_start = match.start()
            return (
                match.group(0)[: start - whole_start]
                + marker
                + match.group(0)[end - whole_start :]
            )
        return marker

    return decide
