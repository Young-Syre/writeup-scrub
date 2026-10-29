"""Runs rules and the hygiene pass over a document, and collects the result."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .config import Config
from .document import Document
from .findings import (
    Finding,
    Severity,
    meets_threshold,
    severity_rank,
    sort_findings,
)
from .hygiene import Hygiene
from .rules import ALL_RULES

MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdx"}
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".obsidian",
    ".trash",
}


@dataclass
class FileResult:
    path: Path
    original: str
    output: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.original != self.output

    @property
    def redactions(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == "redaction"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == "warning"]

    def worst_severity(self) -> Severity | None:
        candidates = [f.severity for f in self.findings if f.kind != "hygiene"]
        if not candidates:
            return None
        return sorted(candidates, key=severity_rank)[0]


def process_text(text: str, path: str, config: Config) -> FileResult:
    """Apply every enabled rule, then the hygiene pass."""
    doc = Document.from_text(text, path=path)
    findings: list[Finding] = []

    for rule in ALL_RULES:
        if not config.is_enabled(rule.id):
            continue
        findings += rule.apply(doc, config.for_rule(rule.id))

    if config.hygiene.get("enabled", True):
        findings += Hygiene().apply(doc, config.hygiene)

    output = doc.render()

    # Attach the resulting line to every finding, so a report shows the effect
    # of a redaction without ever recording the secret itself.
    surviving = doc.line_map()
    for finding in findings:
        finding.path = path
        if finding.context is not None:
            continue
        line = surviving.get(finding.line, "missing")
        if line == "missing":
            continue
        finding.context = line.text.strip() if line is not None else "<line removed>"

    return FileResult(
        path=Path(path), original=text, output=output, findings=sort_findings(findings)
    )


def process_file(path: Path, config: Config) -> FileResult:
    text = path.read_text(encoding="utf-8")
    return process_text(text, str(path), config)


def collect_paths(paths: Iterable[Path]) -> list[Path]:
    """Expand directories to markdown files; explicit files are used as given."""
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_dir():
                    continue
                if any(part in SKIP_DIRECTORIES for part in candidate.parts):
                    continue
                if candidate.suffix.lower() in MARKDOWN_SUFFIXES:
                    out.append(candidate)
        else:
            out.append(path)
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in out:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def gate_failures(results: list[FileResult], threshold: Severity) -> list[Finding]:
    """Findings at or above ``threshold`` (hygiene never counts)."""
    out: list[Finding] = []
    for result in results:
        for finding in result.findings:
            if finding.kind == "hygiene":
                continue
            if meets_threshold(finding.severity, threshold):
                out.append(finding)
    return out
