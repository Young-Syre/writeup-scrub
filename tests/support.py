"""Shared test helpers. Everything here is offline."""

from __future__ import annotations

import copy
from pathlib import Path

from writeup_scrub.config import RULE_DEFAULTS, Config
from writeup_scrub.document import Document
from writeup_scrub.findings import Finding
from writeup_scrub.pipeline import FileResult, process_text
from writeup_scrub.rules import RULES_BY_ID

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def rule_config(rule_id: str, **overrides) -> dict:
    cfg = copy.deepcopy(RULE_DEFAULTS[rule_id])
    cfg.update(overrides)
    return cfg


def run_rule(rule_id: str, text: str, **overrides) -> tuple[str, list[Finding]]:
    """Apply a single rule to ``text``; returns the output and its findings."""
    doc = Document.from_text(text, path=f"<{rule_id}>")
    findings = RULES_BY_ID[rule_id].apply(doc, rule_config(rule_id, **overrides))
    return doc.render(), findings


def only_config(rule_id: str | None, **rule_overrides) -> Config:
    """A config with a single rule (or none) enabled and hygiene off."""
    config = Config()
    for key in config.rules:
        config.rules[key]["enabled"] = key == rule_id
    if rule_id is not None:
        config.rules[rule_id].update(rule_overrides)
    config.hygiene["enabled"] = False
    return config


def run_pipeline(text: str, config: Config, path: str = "t.md") -> FileResult:
    return process_text(text, path, config)


def redactions(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind == "redaction"]


def warnings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.kind == "warning"]
