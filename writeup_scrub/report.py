"""The JSON manifest: an auditable record of what was removed.

By default the manifest records a fingerprint and a short preview of each
redacted value rather than the value itself -- an audit trail that is itself a
leak is not much of an improvement. ``--report-reveal`` opts into plaintext.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .pipeline import FileResult


def build_manifest(
    results: list[FileResult],
    *,
    mode: str,
    config: Config,
    reveal: bool = False,
    outputs: dict[str, str] | None = None,
) -> dict[str, Any]:
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    redactions = warnings = hygiene = 0

    for result in results:
        for finding in result.findings:
            by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
            by_severity[finding.severity.value] = (
                by_severity.get(finding.severity.value, 0) + 1
            )
            if finding.kind == "redaction":
                redactions += 1
            elif finding.kind == "warning":
                warnings += 1
            else:
                hygiene += 1

    files: list[dict[str, Any]] = []
    for result in results:
        entry: dict[str, Any] = {
            "path": str(result.path),
            "changed": result.changed,
            "findings": [f.to_dict(reveal=reveal) for f in result.findings],
        }
        if outputs and str(result.path) in outputs:
            entry["output_path"] = outputs[str(result.path)]
        files.append(entry)

    return {
        "tool": "writeup-scrub",
        "version": __version__,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "mode": mode,
        "config": str(config.source) if config.source else None,
        "plaintext_included": reveal,
        "rules_enabled": sorted(
            rule_id for rule_id in config.rules if config.is_enabled(rule_id)
        ),
        "summary": {
            "files": len(results),
            "files_changed": sum(1 for r in results if r.changed),
            "redactions": redactions,
            "warnings": warnings,
            "hygiene_changes": hygiene,
            "by_rule": dict(sorted(by_rule.items())),
            "by_severity": dict(sorted(by_severity.items())),
        },
        "files": files,
    }


def write_manifest(manifest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
