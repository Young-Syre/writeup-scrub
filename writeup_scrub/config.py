"""Configuration: defaults, ``.writeup-scrub.toml`` loading, and rule toggles.

The schema is validated strictly. An unknown section, rule id or key is an
error rather than a warning: a typo that silently disables a redaction rule in a
CI gate is worse than a failed build.
"""

from __future__ import annotations

import copy
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_FILENAME = ".writeup-scrub.toml"


class ConfigError(Exception):
    """Raised for an unreadable, unparseable or invalid configuration file."""


# --- rule defaults --------------------------------------------------------
#
# Every key here is settable in [rules.WSxxx]. Anything not here is rejected.

RULE_DEFAULTS: dict[str, dict[str, Any]] = {
    "WS001": {
        "enabled": True,
        "marker": "[REDACTED: platform flag]",
        # How many preceding non-blank lines may establish flag/hash context.
        "context_lines": 5,
        # Redact a bare 32-hex string that sits alone on a line with no
        # surrounding context at all. Off by default: unlabelled hex is more
        # often a hash than a flag, so the default is to warn instead.
        "redact_bare_hex": False,
        "warn_on_bare_hex": True,
        # Braced flags (HTB{...}, flag{...}) are unambiguous and always redacted.
        "redact_braced_flags": True,
        "extra_flag_keywords": [],
        "extra_hash_keywords": [],
        # Well-known constants that are never flags, whatever the context.
        "never_redact": [
            "aad3b435b51404eeaad3b435b51404ee",  # empty LM hash
            "31d6cfe0d16ae931b73c59d7e0c089c0",  # empty NT hash
            "d41d8cd98f00b204e9800998ecf8427e",  # md5 of empty string
        ],
    },
    "WS002": {
        "enabled": True,
        "marker": "[REDACTED: secret]",
        "private_key_marker": "[REDACTED: private key material]",
        "detect_jwts": True,
        "detect_private_keys": True,
        # Session cookies are *target* artefacts in most writeups (a PHPSESSID
        # belonging to the box you just pwned is the finding), so cookie
        # stripping is opt-in rather than default.
        "detect_session_cookies": False,
        "disabled_patterns": [],
    },
    "WS003": {
        "enabled": True,
        "placeholder": "operator",
        # Empty means "any username". Set this to your own usernames so the
        # rule never rewrites a *target* machine's home directory.
        "users": [],
        # Never rewritten. The Windows defaults are target-side accounts.
        "preserve_users": [
            "operator",
            "Public",
            "Default",
            "Default User",
            "All Users",
            "Administrator",
        ],
    },
    "WS004": {
        "enabled": True,
        "email_marker": "[REDACTED: email]",
        "phone_marker": "[REDACTED: phone]",
        "detect_emails": True,
        "detect_phones": True,
        # Addresses kept verbatim (your contact address, for example).
        "preserve_addresses": [],
        # Domains kept verbatim because they belong to the target, not to you.
        "preserve_domains": [
            "htb",
            "htb.local",
            "thm",
            "vl",
            "lab",
            "local",
            "localdomain",
            "example.com",
            "example.org",
            "example.net",
            "test",
            "invalid",
        ],
    },
    "WS005": {
        "enabled": True,
        "marker": "[REDACTED: operator address]",
        # Nothing is stripped until you say so. Put your tunnel range here.
        "strip_cidrs": [],
        # Lab ranges that are part of the narrative. Longest prefix wins, so a
        # strip of 10.10.14.0/24 still beats a preserve of 10.10.0.0/16.
        "preserve_cidrs": [
            "10.10.0.0/16",
            "10.129.0.0/16",
            "10.127.0.0/16",
            "127.0.0.0/8",
            "192.168.0.0/16",
            "172.16.0.0/12",
        ],
    },
    "WS006": {
        "enabled": True,
        "drop_frontmatter_keys": ["tags", "status", "type", "aliases"],
        "drop_empty_frontmatter": True,
        # "text" -> [[Page|Alias]] becomes Alias
        # "link" -> [[Page|Alias]] becomes [Alias](Page.md)
        "wikilink_mode": "text",
        "wikilink_extension": ".md",
        "convert_callouts": True,
        "strip_comments": True,
    },
    "WS007": {
        "enabled": True,
        "markers": ["TODO", "FIXME", "XXX", "HACK", "WIP", "NOTE TO SELF"],
        "phrases": [
            "ask in discord",
            "asked in discord",
            "got hint from",
            "hint from",
            "nudge from",
            "got a nudge",
            "still stuck",
            "no idea why this works",
            "not sure why this works",
            "clean this up later",
        ],
        "warn_empty_sections": True,
    },
}

HYGIENE_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "close_unterminated_fences": True,
    "infer_fence_language": True,
    "normalise_headings": True,
    "strip_trailing_whitespace": True,
    "max_consecutive_blank_lines": 1,
    "default_fence_language": "text",
}

RETIREMENT_DEFAULTS: dict[str, Any] = {
    "platform": "htb",
    "timeout": 15.0,
}

LIST_KEYS = {
    key
    for settings in RULE_DEFAULTS.values()
    for key, value in settings.items()
    if isinstance(value, list)
}


@dataclass
class Config:
    rules: dict[str, dict[str, Any]] = field(
        default_factory=lambda: copy.deepcopy(RULE_DEFAULTS)
    )
    hygiene: dict[str, Any] = field(default_factory=lambda: dict(HYGIENE_DEFAULTS))
    retirement: dict[str, Any] = field(default_factory=lambda: dict(RETIREMENT_DEFAULTS))
    source: Path | None = None

    # -- accessors ---------------------------------------------------------

    def for_rule(self, rule_id: str) -> dict[str, Any]:
        return self.rules[rule_id]

    def is_enabled(self, rule_id: str) -> bool:
        return bool(self.rules.get(rule_id, {}).get("enabled", False))

    def apply_toggles(self, enable: list[str], disable: list[str]) -> None:
        """Apply ``--enable``/``--disable`` overrides (CLI beats file)."""
        for rule_id in enable:
            key = rule_id.strip().upper()
            if key not in self.rules:
                raise ConfigError(f"unknown rule id in --enable: {rule_id}")
            self.rules[key]["enabled"] = True
        for rule_id in disable:
            key = rule_id.strip().upper()
            if key not in self.rules:
                raise ConfigError(f"unknown rule id in --disable: {rule_id}")
            self.rules[key]["enabled"] = False

    # -- loading -----------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ConfigError(f"cannot read config {path}: {exc}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
        config = cls.from_dict(raw, source=path)
        return config

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source: Path | None = None) -> "Config":
        config = cls(source=source)
        known_sections = {"rules", "hygiene", "retirement"}
        unknown = set(raw) - known_sections
        if unknown:
            raise ConfigError(
                "unknown config section(s): "
                + ", ".join(sorted(unknown))
                + f" (known: {', '.join(sorted(known_sections))})"
            )

        rules = raw.get("rules", {})
        if not isinstance(rules, dict):
            raise ConfigError("[rules] must be a table")
        for rule_id, settings in rules.items():
            key = rule_id.upper()
            if key not in RULE_DEFAULTS:
                raise ConfigError(
                    f"unknown rule id [rules.{rule_id}]"
                    f" (known: {', '.join(sorted(RULE_DEFAULTS))})"
                )
            if not isinstance(settings, dict):
                raise ConfigError(f"[rules.{rule_id}] must be a table")
            for setting, value in settings.items():
                if setting not in RULE_DEFAULTS[key]:
                    raise ConfigError(
                        f"unknown key '{setting}' in [rules.{rule_id}]"
                        f" (known: {', '.join(sorted(RULE_DEFAULTS[key]))})"
                    )
                expected = RULE_DEFAULTS[key][setting]
                _check_type(f"rules.{rule_id}.{setting}", value, expected)
                config.rules[key][setting] = value

        for section, defaults, target in (
            ("hygiene", HYGIENE_DEFAULTS, config.hygiene),
            ("retirement", RETIREMENT_DEFAULTS, config.retirement),
        ):
            values = raw.get(section, {})
            if not isinstance(values, dict):
                raise ConfigError(f"[{section}] must be a table")
            for setting, value in values.items():
                if setting not in defaults:
                    raise ConfigError(
                        f"unknown key '{setting}' in [{section}]"
                        f" (known: {', '.join(sorted(defaults))})"
                    )
                _check_type(f"{section}.{setting}", value, defaults[setting])
                target[setting] = value

        if config.rules["WS006"]["wikilink_mode"] not in {"text", "link"}:
            raise ConfigError(
                "rules.WS006.wikilink_mode must be either 'text' or 'link'"
            )
        return config

    @classmethod
    def discover(cls, explicit: Path | None, start: Path | None = None) -> "Config":
        """Explicit path, else the nearest ``.writeup-scrub.toml`` upwards."""
        if explicit is not None:
            if not explicit.exists():
                raise ConfigError(f"config file not found: {explicit}")
            return cls.load(explicit)
        here = (start or Path.cwd()).resolve()
        for directory in [here, *here.parents]:
            candidate = directory / CONFIG_FILENAME
            if candidate.is_file():
                return cls.load(candidate)
        return cls()


def _check_type(dotted: str, value: Any, expected: Any) -> None:
    if isinstance(expected, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{dotted} must be a boolean")
        return
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{dotted} must be a number")
        return
    if isinstance(expected, str):
        if not isinstance(value, str):
            raise ConfigError(f"{dotted} must be a string")
        return
    if isinstance(expected, list):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{dotted} must be a list of strings")
        return
    raise ConfigError(f"{dotted}: unsupported setting type")  # pragma: no cover


TEMPLATE = '''\
# .writeup-scrub.toml -- configuration for writeup-scrub.
#
# Every rule is independently toggleable. Keys are validated strictly: a typo
# is an error, so a rule cannot be silently disabled in a CI gate.
#
#   writeup-scrub rules            # list rule ids and severities
#   writeup-scrub scan writeups/   # the publication gate (exit 1 on CRITICAL)

# --- WS001: platform flags (CRITICAL) ---------------------------------------
# Context-aware. A 32-hex string is redacted when the surrounding text says
# "flag" and kept when it says "hash" -- NTLM hashes and md5 checksums are
# legitimate content in a retired-machine writeup.
[rules.WS001]
enabled = true
marker = "[REDACTED: platform flag]"
context_lines = 5
# A bare 32-hex string alone on a line, with no context at all, is ambiguous.
# Default: warn and leave it, so a human decides.
redact_bare_hex = false
warn_on_bare_hex = true
redact_braced_flags = true
# extra_flag_keywords = ["pwn3d"]
# extra_hash_keywords = ["pbkdf2"]

# --- WS002: live secrets (CRITICAL) -----------------------------------------
[rules.WS002]
enabled = true
marker = "[REDACTED: secret]"
detect_jwts = true
detect_private_keys = true
# Target session cookies are usually the finding itself, so this is opt-in.
detect_session_cookies = false
# Turn off individual detectors by name, e.g. ["openai"].
# disabled_patterns = []

# --- WS003: local paths (MEDIUM) --------------------------------------------
# /home/<you>/... becomes /home/operator/..., trailing path preserved.
[rules.WS003]
enabled = true
placeholder = "operator"
# STRONGLY RECOMMENDED: list your own usernames. With an empty list the rule
# rewrites *every* home directory, including a target machine's /home/svc_sql.
# users = ["yourname"]
users = []

# --- WS004: personal identifiers (MEDIUM) -----------------------------------
[rules.WS004]
enabled = true
detect_emails = true
detect_phones = true
# Addresses you want kept (your public contact address, for instance).
# preserve_addresses = ["you@yourdomain.com"]
# In-universe domains that belong to the target machine, not to you.
# preserve_domains = ["htb", "thm", "local", "example.com"]

# --- WS005: operator network details (HIGH) ---------------------------------
# Nothing is stripped until you name a range. Longest prefix wins, so a strip
# of 10.10.14.0/24 beats the preserved 10.10.0.0/16 lab range.
[rules.WS005]
enabled = true
# strip_cidrs = ["10.10.14.0/24", "10.10.16.0/24"]
strip_cidrs = []

# --- WS006: private-note artefacts (LOW) ------------------------------------
[rules.WS006]
enabled = true
drop_frontmatter_keys = ["tags", "status", "type", "aliases"]
wikilink_mode = "text"   # or "link" for [Alias](Page.md)
convert_callouts = true
strip_comments = true

# --- WS007: unresolved scratch content (INFO, warnings only) ----------------
# Never rewrites anything -- reports lines for human review.
[rules.WS007]
enabled = true
markers = ["TODO", "FIXME", "XXX", "HACK", "WIP", "NOTE TO SELF"]
warn_empty_sections = true

# --- markdown hygiene -------------------------------------------------------
[hygiene]
enabled = true
close_unterminated_fences = true
infer_fence_language = true
normalise_headings = true
strip_trailing_whitespace = true
max_consecutive_blank_lines = 1

# --- retirement check (networked, opt-in via --check-retired) ---------------
# Needs your own token in HTB_TOKEN. No token is bundled with this tool.
[retirement]
platform = "htb"
timeout = 15.0
'''
