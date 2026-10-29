"""Command line interface.

Modes
-----
``scan``   report only; exits non-zero when a redaction at or above
           ``--fail-on`` (default: critical) would fire. This is the
           pre-commit / CI publication gate.
``clean``  write sanitised copies to ``--out DIR``. Never writes in place
           unless ``--in-place`` is passed explicitly.
``diff``   unified diff of what would change.
``init``   write a commented ``.writeup-scrub.toml``.
``rules``  list the rules, their severities and what they preserve.

Exit codes
----------
0 clean, 1 gate failed, 2 usage/config/IO error, 3 retirement check failed.
"""

from __future__ import annotations

import argparse
import difflib
import os
import sys
from pathlib import Path
from typing import Sequence, TextIO

from . import __version__
from .config import CONFIG_FILENAME, Config, ConfigError, TEMPLATE
from .findings import Finding, Severity, severity_rank
from .pipeline import FileResult, collect_paths, gate_failures, process_file
from .platforms import RetirementCheckError, get_adapter
from .report import build_manifest, write_manifest
from .rules import ALL_RULES

EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
EXIT_RETIREMENT = 3

SEVERITY_CHOICES = [s.value for s in Severity] + ["any", "none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="writeup-scrub",
        description="Sanitise security writeups and CTF notes before publication.",
    )
    parser.add_argument("--version", action="version", version=f"writeup-scrub {__version__}")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("paths", nargs="+", type=Path, help="files or directories")
        sub.add_argument("--config", type=Path, help=f"path to {CONFIG_FILENAME}")
        sub.add_argument("--enable", default="", help="comma-separated rule ids to force on")
        sub.add_argument("--disable", default="", help="comma-separated rule ids to force off")
        sub.add_argument("--no-hygiene", action="store_true", help="skip the markdown hygiene pass")
        sub.add_argument("--report", type=Path, help="write a JSON manifest of every redaction")
        sub.add_argument(
            "--report-reveal",
            action="store_true",
            help="include redacted plaintext in the manifest (off by default)",
        )
        sub.add_argument("--check-retired", action="store_true", help="verify the machine is retired (network)")
        sub.add_argument("--machine", help="machine name for --check-retired")
        sub.add_argument("--platform", default=None, help="retirement platform (default: htb)")
        sub.add_argument("--token-env", default=None, help="env var holding the API token")
        sub.add_argument("--quiet", action="store_true", help="only print the summary")

    scan = subparsers.add_parser("scan", help="report only; the CI publication gate")
    add_common(scan)
    scan.add_argument(
        "--fail-on",
        default="critical",
        choices=SEVERITY_CHOICES,
        help="minimum severity that fails the gate (default: critical)",
    )
    scan.add_argument("--json", action="store_true", help="print the manifest to stdout")

    clean = subparsers.add_parser("clean", help="write sanitised copies")
    add_common(clean)
    clean.add_argument("--out", type=Path, help="output directory (required unless --in-place)")
    clean.add_argument(
        "--in-place",
        action="store_true",
        help="overwrite the input files (must be passed explicitly)",
    )

    diff = subparsers.add_parser("diff", help="unified diff of what would change")
    add_common(diff)

    init = subparsers.add_parser("init", help=f"write a commented {CONFIG_FILENAME}")
    init.add_argument("--path", type=Path, default=Path(CONFIG_FILENAME))
    init.add_argument("--force", action="store_true", help="overwrite an existing file")

    subparsers.add_parser("rules", help="list the redaction rules")
    return parser


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    out = stdout or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == "init":
        return _init(args, out)
    if args.mode == "rules":
        return _rules(out)

    try:
        config = Config.discover(args.config)
        config.apply_toggles(
            [value for value in args.enable.split(",") if value.strip()],
            [value for value in args.disable.split(",") if value.strip()],
        )
    except ConfigError as exc:
        print(f"writeup-scrub: config error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.no_hygiene:
        config.hygiene["enabled"] = False

    paths = collect_paths(args.paths)
    missing = [path for path in paths if not path.is_file()]
    if missing:
        for path in missing:
            print(f"writeup-scrub: no such file: {path}", file=sys.stderr)
        return EXIT_USAGE
    if not paths:
        print("writeup-scrub: no markdown files found", file=sys.stderr)
        return EXIT_USAGE

    if args.check_retired:
        code = _check_retired(args, config, paths, out)
        if code != EXIT_OK:
            return code

    try:
        results = [process_file(path, config) for path in paths]
    except (OSError, UnicodeDecodeError) as exc:
        print(f"writeup-scrub: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ValueError as exc:  # invalid CIDR in config, for example
        print(f"writeup-scrub: config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.mode == "scan":
        return _scan(args, config, results, out)
    if args.mode == "diff":
        return _diff(args, config, results, out)
    return _clean(args, config, results, out)


# --- modes ----------------------------------------------------------------


def _scan(args, config: Config, results: list[FileResult], out: TextIO) -> int:
    if args.json:
        import json

        manifest = build_manifest(
            results, mode="scan", config=config, reveal=args.report_reveal
        )
        print(json.dumps(manifest, indent=2), file=out)
    elif not args.quiet:
        _print_findings(results, out)
    _maybe_write_report(args, config, results, mode="scan")

    threshold = args.fail_on
    if threshold == "none":
        if not args.quiet and not args.json:
            print(_summary(results), file=out)
        return EXIT_OK
    severity = Severity.INFO if threshold == "any" else Severity(threshold)
    failures = gate_failures(results, severity)
    if not args.quiet and not args.json:
        print(_summary(results), file=out)
    if failures:
        worst = sorted({f.rule for f in failures})
        print(
            f"writeup-scrub: publication gate FAILED: {len(failures)} finding(s) at or "
            f"above {severity.value} ({', '.join(worst)})",
            file=sys.stderr,
        )
        return EXIT_GATE
    return EXIT_OK


def _diff(args, config: Config, results: list[FileResult], out: TextIO) -> int:
    any_change = False
    for result in results:
        if not result.changed:
            continue
        any_change = True
        diff = difflib.unified_diff(
            result.original.splitlines(keepends=True),
            result.output.splitlines(keepends=True),
            fromfile=str(result.path),
            tofile=f"{result.path} (scrubbed)",
        )
        out.writelines(diff)
    _maybe_write_report(args, config, results, mode="diff")
    if not any_change and not args.quiet:
        print("writeup-scrub: nothing would change", file=out)
    return EXIT_OK


def _clean(args, config: Config, results: list[FileResult], out: TextIO) -> int:
    if not args.in_place and args.out is None:
        print(
            "writeup-scrub: clean needs --out DIR, or --in-place to overwrite the "
            "inputs (never implied)",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if args.in_place and args.out is not None:
        print("writeup-scrub: --out and --in-place are mutually exclusive", file=sys.stderr)
        return EXIT_USAGE

    outputs: dict[str, str] = {}
    base = _common_base([result.path for result in results]) if args.out else None
    for result in results:
        if args.in_place:
            destination = result.path
        else:
            relative = _relative_to(result.path, base)
            destination = args.out / relative
            if destination.resolve() == result.path.resolve():
                print(
                    f"writeup-scrub: refusing to write over {result.path} -- "
                    "--out resolves to the input file; pass --in-place to mean that",
                    file=sys.stderr,
                )
                return EXIT_USAGE
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(result.output, encoding="utf-8")
        except OSError as exc:
            print(f"writeup-scrub: cannot write {destination}: {exc}", file=sys.stderr)
            return EXIT_USAGE
        outputs[str(result.path)] = str(destination)
        if not args.quiet:
            marker = "changed" if result.changed else "unchanged"
            print(f"wrote {destination} ({marker})", file=out)

    if not args.quiet:
        _print_findings(results, out)
        print(_summary(results), file=out)
    _maybe_write_report(args, config, results, mode="clean", outputs=outputs)
    return EXIT_OK


def _init(args, out: TextIO) -> int:
    path: Path = args.path
    if path.exists() and not args.force:
        print(f"writeup-scrub: {path} already exists (use --force)", file=sys.stderr)
        return EXIT_USAGE
    try:
        path.write_text(TEMPLATE, encoding="utf-8")
    except OSError as exc:
        print(f"writeup-scrub: cannot write {path}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"wrote {path}", file=out)
    return EXIT_OK


def _rules(out: TextIO) -> int:
    print(f"{'id':6} {'severity':9} {'rule':28} catches", file=out)
    for rule in ALL_RULES:
        print(
            f"{rule.id:6} {rule.severity.value:9} {rule.title:28} {rule.catches}",
            file=out,
        )
    print("\nMD-FENCE / MD-LANG / MD-HEADING / MD-WS / MD-BLANK: markdown hygiene (info)", file=out)
    return EXIT_OK


# --- retirement -----------------------------------------------------------


def _check_retired(args, config: Config, paths: list[Path], out: TextIO) -> int:
    platform_name = args.platform or config.retirement.get("platform", "htb")
    try:
        adapter_class = get_adapter(platform_name)
    except RetirementCheckError as exc:
        print(f"writeup-scrub: {exc}", file=sys.stderr)
        return EXIT_RETIREMENT

    machine = args.machine or paths[0].stem
    if not args.machine and not args.quiet:
        print(
            f"writeup-scrub: --machine not given, using {machine!r} from {paths[0].name}",
            file=out,
        )
    token_env = args.token_env or adapter_class.token_env
    adapter = adapter_class(token=os.environ.get(token_env))
    try:
        result = adapter.check(machine, timeout=float(config.retirement.get("timeout", 15.0)))
    except (RetirementCheckError, OSError) as exc:
        print(
            f"writeup-scrub: retirement check could not be completed: {exc}\n"
            "            refusing to assume the machine is retired",
            file=sys.stderr,
        )
        return EXIT_RETIREMENT
    if not result.retired:
        print(
            f"writeup-scrub: {machine!r} is NOT in the {platform_name} retired list "
            f"({result.total_known} machines checked) -- publishing a writeup for an "
            "active machine breaks the platform rules",
            file=sys.stderr,
        )
        return EXIT_RETIREMENT
    if not args.quiet:
        print(
            f"retirement check: {result.matched_name} is retired on {platform_name} "
            f"({result.total_known} retired machines known)",
            file=out,
        )
    return EXIT_OK


# --- output helpers -------------------------------------------------------


def _print_findings(results: list[FileResult], out: TextIO) -> None:
    for result in results:
        visible = [f for f in result.findings if f.kind != "hygiene"]
        hygiene = len(result.findings) - len(visible)
        if not visible and not hygiene:
            continue
        print(f"\n{result.path}", file=out)
        for finding in sorted(visible, key=lambda f: (f.line, severity_rank(f.severity))):
            print(f"  {_format_finding(finding)}", file=out)
        if hygiene:
            print(f"  (+{hygiene} markdown hygiene change(s))", file=out)


def _format_finding(finding: Finding) -> str:
    head = f"{finding.rule} {finding.severity.value:8} line {finding.line:<5} {finding.message}"
    if finding.kind == "redaction" and finding.context:
        return f"{head}\n      -> {finding.context[:160]}"
    return head


def _summary(results: list[FileResult]) -> str:
    redactions = sum(len(r.redactions) for r in results)
    warnings = sum(len(r.warnings) for r in results)
    critical = sum(
        1
        for r in results
        for f in r.findings
        if f.severity is Severity.CRITICAL and f.kind != "hygiene"
    )
    hygiene = sum(1 for r in results for f in r.findings if f.kind == "hygiene")
    return (
        f"\n{len(results)} file(s) · {redactions} redaction(s) ({critical} critical) · "
        f"{warnings} warning(s) · {hygiene} hygiene change(s)"
    )


def _maybe_write_report(
    args, config: Config, results: list[FileResult], *, mode: str, outputs=None
) -> None:
    if not getattr(args, "report", None):
        return
    manifest = build_manifest(
        results, mode=mode, config=config, reveal=args.report_reveal, outputs=outputs
    )
    write_manifest(manifest, args.report)


def _common_base(paths: list[Path]) -> Path:
    directories = [path.resolve().parent for path in paths]
    if not directories:
        return Path(".")
    base = directories[0]
    for directory in directories[1:]:
        while not _is_relative(directory, base):
            if base.parent == base:
                return base
            base = base.parent
    return base


def _is_relative(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _relative_to(path: Path, base: Path | None) -> Path:
    if base is None:
        return Path(path.name)
    try:
        return path.resolve().relative_to(base)
    except ValueError:
        return Path(path.name)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
