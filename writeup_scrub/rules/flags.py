"""WS001 -- platform flags, without eating every hash in the writeup.

A retired-machine writeup is *full* of 32-character hex strings that must
survive publication: NTLM hashes from ``secretsdump``, md5 checksums, the empty
LM hash, MD4 digests. A blanket 32-hex redaction would destroy the technical
content of the writeup, so this rule decides per match, using the nearest
label.

Resolution order for a 32-hex candidate:

1. the text *before* the match on the same line -- nearest keyword wins
2. the text *after* the match on the same line
3. preceding lines (bounded by the enclosing code fence, ``context_lines`` deep)
4. nothing matched -> keep it, and warn if the hex sits alone on a line

Braced flags (``HTB{...}``, ``flag{...}``) are unambiguous and always redacted.
"""

from __future__ import annotations

import re
from typing import Any

from ..document import ATX_HEADING_RE, FENCE_RE, Document, Line
from ..findings import Finding, Severity
from .base import Rule, keyword_pattern, substitute_lines

HEX32_RE = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{32})(?![0-9A-Za-z])")

BRACED_FLAG_RE = re.compile(
    r"\b(?:HTB|THM|FLAG|flag|CTF|picoCTF|pico|KEY|key)\{[^}\n]{1,256}\}"
)

# Signals that the nearby hex is a platform flag.
FLAG_KEYWORDS = (
    "flag",
    "flags",
    "user.txt",
    "root.txt",
    "proof.txt",
    "user_flag",
    "root_flag",
    "userflag",
    "rootflag",
    "user-flag",
    "root-flag",
    "own user",
    "own root",
    "owned user",
    "owned root",
    "submit",
)

# Signals that the nearby hex is a hash, checksum or other legitimate artefact.
HASH_KEYWORDS = (
    "hash",
    "hashes",
    "hashed",
    "nthash",
    "nt hash",
    "nt-hash",
    "lm hash",
    "ntlm",
    "ntlmv1",
    "ntlmv2",
    "netntlm",
    "md5",
    "md5sum",
    "md4",
    "checksum",
    "digest",
    "hashcat",
    "john",
    "crackstation",
    "crack",
    "cracked",
    "cracking",
    "rainbow table",
    "secretsdump",
    "mimikatz",
    "pwdump",
    "lsass",
    "krbtgt",
    "dcsync",
    "/etc/shadow",
    "shadow file",
    "pass-the-hash",
    "pth",
    "etag",
    "uuid",
    "guid",
    "objectguid",
    "fingerprint",
    "thumbprint",
    "mscash",
    "dcc2",
    "-m 1000",
    "-m 5600",
    "commit",
    "revision",
    "machine account",
    "password hash",
    "session key",
    "nonce",
    "salt",
)


class FlagRule(Rule):
    id = "WS001"
    severity = Severity.CRITICAL
    title = "platform flags"
    catches = (
        "32-hex strings in flag context (`User flag:`, `root.txt` output, "
        "flag-submission blocks) and braced flags like `HTB{...}`"
    )
    preserves = (
        "NTLM/NT/LM hashes, md5 checksums, MD4 digests, UUIDs, ETags and any "
        "32-hex string whose nearest label is a hash"
    )

    def apply(self, doc: Document, cfg: dict[str, Any]) -> list[Finding]:
        flag_words = tuple(FLAG_KEYWORDS) + tuple(cfg.get("extra_flag_keywords", []))
        hash_words = tuple(HASH_KEYWORDS) + tuple(cfg.get("extra_hash_keywords", []))
        flag_re = keyword_pattern(flag_words)
        hash_re = keyword_pattern(hash_words)
        marker = cfg["marker"]
        never = {value.lower() for value in cfg.get("never_redact", [])}
        context_lines = int(cfg.get("context_lines", 5))

        findings: list[Finding] = []
        bare_hex_warnings: list[Finding] = []

        if cfg.get("redact_braced_flags", True):
            findings += substitute_lines(
                doc,
                BRACED_FLAG_RE,
                lambda match, index, line: marker,
                rule=self.id,
                severity=self.severity,
                message="braced flag redacted",
            )

        def decide(match: re.Match[str], index: int, line: Line) -> str | None:
            value = match.group(0)
            if value.lower() in never:
                return None
            verdict = self._classify(
                doc,
                index,
                line,
                match,
                flag_re=flag_re,
                hash_re=hash_re,
                context_lines=context_lines,
            )
            if verdict == "flag":
                return marker
            if verdict is None and self._is_alone_on_line(line, match):
                if cfg.get("redact_bare_hex", False):
                    return marker
                if cfg.get("warn_on_bare_hex", True):
                    bare_hex_warnings.append(
                        Finding(
                            rule=self.id,
                            severity=Severity.LOW,
                            line=line.number,
                            kind="warning",
                            message=(
                                "unlabelled 32-hex string alone on a line -- could be "
                                "a flag or a hash; review it by hand"
                            ),
                        )
                    )
            return None

        findings += substitute_lines(
            doc,
            HEX32_RE,
            decide,
            rule=self.id,
            severity=self.severity,
            message="platform flag redacted",
        )
        return findings + bare_hex_warnings

    # -- classification ----------------------------------------------------

    def _classify(
        self,
        doc: Document,
        index: int,
        line: Line,
        match: re.Match[str],
        *,
        flag_re: re.Pattern[str],
        hash_re: re.Pattern[str],
        context_lines: int,
    ) -> str | None:
        """Return ``"flag"``, ``"hash"`` or ``None`` (undecided)."""
        before = line.text[: match.start()]
        verdict = _nearest(before, flag_re, hash_re, prefer="last")
        if verdict is not None:
            return verdict

        after = line.text[match.end() :]
        verdict = _nearest(after, flag_re, hash_re, prefer="first")
        if verdict is not None:
            return verdict

        return self._context_verdict(
            doc, index, flag_re=flag_re, hash_re=hash_re, limit=context_lines
        )

    def _context_verdict(
        self,
        doc: Document,
        index: int,
        *,
        flag_re: re.Pattern[str],
        hash_re: re.Pattern[str],
        limit: int,
    ) -> str | None:
        """Walk back over preceding non-blank lines; nearest signal wins.

        Inside a fenced block the walk stops at the fence opener, then continues
        with the prose immediately above the fence -- that covers both

            $ cat /root/root.txt        (command inside the block)
            8a1f...

        and

            The root flag:              (prose above the block)
            ```
            8a1f...
            ```
        """
        fence = doc.fence_containing(index)
        seen = 0
        cursor = index - 1
        boundary = fence.open_idx if fence is not None else -1

        while cursor > boundary and seen < limit:
            line = doc.lines[cursor]
            cursor -= 1
            if line.dropped:
                continue
            text = line.text.strip()
            if not text:
                continue
            verdict = _nearest(line.text, flag_re, hash_re, prefer="last")
            if verdict is not None:
                return verdict
            seen += 1

        if fence is None:
            return None

        # Continue above the fence opener, through the prose that introduces the
        # block. The walk stops at a heading or at another fence delimiter: the
        # paragraph above *this* block is context, an earlier code block is not.
        cursor = fence.open_idx - 1
        while cursor >= 0 and seen < limit:
            line = doc.lines[cursor]
            cursor -= 1
            if line.dropped:
                continue
            text = line.text.strip()
            if not text:
                continue
            if FENCE_RE.match(line.text):
                return None
            verdict = _nearest(line.text, flag_re, hash_re, prefer="last")
            if verdict is not None or ATX_HEADING_RE.match(line.text):
                return verdict
            seen += 1
        return None

    @staticmethod
    def _is_alone_on_line(line: Line, match: re.Match[str]) -> bool:
        stripped = line.text.strip()
        return stripped == match.group(0)


def _nearest(
    text: str,
    flag_re: re.Pattern[str],
    hash_re: re.Pattern[str],
    *,
    prefer: str,
) -> str | None:
    """Which keyword class sits closest to the candidate in ``text``."""
    best: tuple[int, str] | None = None
    for kind, pattern in (("flag", flag_re), ("hash", hash_re)):
        for match in pattern.finditer(text):
            position = match.start()
            if best is None:
                best = (position, kind)
            elif prefer == "last" and position > best[0]:
                best = (position, kind)
            elif prefer == "first" and position < best[0]:
                best = (position, kind)
    return best[1] if best else None
