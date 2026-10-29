"""CLI behaviour: exit codes, modes, and the never-write-in-place guarantee."""

import io
import json
import os
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from writeup_scrub.cli import EXIT_GATE, EXIT_OK, EXIT_RETIREMENT, EXIT_USAGE, main

from .support import fixture

FLAG_DOC = "# Box\n\nUser flag: 0123456789abcdef0123456789abcdef\n"
CLEAN_DOC = "# Box\n\nNothing sensitive in here at all.\n"


def run(argv):
    """Run the CLI, returning (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stderr(err):
        code = main(argv, stdout=out)
    return code, out.getvalue(), err.getvalue()


class ScanGateTests(unittest.TestCase):
    def test_scan_fails_on_a_critical_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            code, out, err = run(["scan", str(path)])
            self.assertEqual(code, EXIT_GATE)
            self.assertIn("WS001", out)
            self.assertIn("gate FAILED", err)

    def test_scan_passes_on_a_clean_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(CLEAN_DOC, encoding="utf-8")
            code, _, err = run(["scan", str(path)])
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(err, "")

    def test_scan_never_modifies_the_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            run(["scan", str(path)])
            self.assertEqual(path.read_text(encoding="utf-8"), FLAG_DOC)

    def test_fail_on_can_be_lowered(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text("# T\n\nTODO: finish\n", encoding="utf-8")
            self.assertEqual(run(["scan", str(path)])[0], EXIT_OK)
            self.assertEqual(run(["scan", str(path), "--fail-on", "info"])[0], EXIT_GATE)

    def test_fail_on_none_always_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            self.assertEqual(run(["scan", str(path), "--fail-on", "none"])[0], EXIT_OK)

    def test_disabled_rule_passes_the_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            code, _, _ = run(["scan", str(path), "--disable", "WS001"])
            self.assertEqual(code, EXIT_OK)

    def test_json_output_is_a_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            code, out, _ = run(["scan", str(path), "--json"])
            self.assertEqual(code, EXIT_GATE)
            manifest = json.loads(out)
            self.assertEqual(manifest["summary"]["redactions"], 1)

    def test_console_output_never_prints_the_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            _, out, err = run(["scan", str(path)])
            self.assertNotIn("0123456789abcdef0123456789abcdef", out + err)

    def test_directory_is_recursed_for_markdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nested").mkdir()
            (root / "nested" / "a.md").write_text(FLAG_DOC, encoding="utf-8")
            (root / "notes.txt").write_text(FLAG_DOC, encoding="utf-8")
            code, out, _ = run(["scan", str(root)])
            self.assertEqual(code, EXIT_GATE)
            self.assertIn("a.md", out)
            self.assertNotIn("notes.txt", out)

    def test_missing_file_is_a_usage_error(self):
        code, _, err = run(["scan", "/nonexistent/path.md"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("no such file", err)

    def test_bad_rule_toggle_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(CLEAN_DOC, encoding="utf-8")
            code, _, err = run(["scan", str(path), "--disable", "WS999"])
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("config error", err)


class CleanTests(unittest.TestCase):
    def test_clean_refuses_without_out_or_in_place(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "box.md"
            path.write_text(FLAG_DOC, encoding="utf-8")
            code, _, err = run(["clean", str(path)])
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("--out", err)
            self.assertIn("--in-place", err)
            self.assertEqual(
                path.read_text(encoding="utf-8"), FLAG_DOC, "input was modified"
            )

    def test_clean_writes_to_out_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            destination = root / "public"
            code, out, _ = run(["clean", str(source), "--out", str(destination)])
            self.assertEqual(code, EXIT_OK)
            self.assertEqual(source.read_text(encoding="utf-8"), FLAG_DOC)
            written = (destination / "box.md").read_text(encoding="utf-8")
            self.assertIn("[REDACTED: platform flag]", written)
            self.assertNotIn("0123456789abcdef0123456789abcdef", written)
            self.assertIn("wrote", out)

    def test_clean_preserves_directory_structure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src" / "htb").mkdir(parents=True)
            (root / "src" / "htb" / "box.md").write_text(FLAG_DOC, encoding="utf-8")
            (root / "src" / "top.md").write_text(FLAG_DOC, encoding="utf-8")
            destination = root / "out"
            code, _, _ = run(["clean", str(root / "src"), "--out", str(destination)])
            self.assertEqual(code, EXIT_OK)
            self.assertTrue((destination / "htb" / "box.md").is_file())
            self.assertTrue((destination / "top.md").is_file())

    def test_in_place_requires_the_explicit_flag(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            # --out pointing at the input's own directory must be refused
            code, _, err = run(["clean", str(source), "--out", str(root)])
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("refusing to write over", err)
            self.assertEqual(source.read_text(encoding="utf-8"), FLAG_DOC)

    def test_in_place_overwrites_when_asked(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            code, _, _ = run(["clean", str(source), "--in-place"])
            self.assertEqual(code, EXIT_OK)
            written = source.read_text(encoding="utf-8")
            self.assertIn("[REDACTED: platform flag]", written)

    def test_out_and_in_place_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            code, _, err = run(
                ["clean", str(source), "--in-place", "--out", str(Path(temporary) / "o")]
            )
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("mutually exclusive", err)

    def test_report_manifest_is_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            report = root / "audit" / "manifest.json"
            code, _, _ = run(
                [
                    "clean",
                    str(source),
                    "--out",
                    str(root / "public"),
                    "--report",
                    str(report),
                ]
            )
            self.assertEqual(code, EXIT_OK)
            manifest = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(manifest["mode"], "clean")
            self.assertEqual(manifest["summary"]["redactions"], 1)
            self.assertIn("output_path", manifest["files"][0])
            self.assertNotIn(
                "0123456789abcdef0123456789abcdef", report.read_text(encoding="utf-8")
            )


class DiffTests(unittest.TestCase):
    def test_diff_shows_the_change_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            code, out, _ = run(["diff", str(source)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("--- ", out)
            self.assertIn("+++ ", out)
            self.assertIn("+User flag: [REDACTED: platform flag]", out)
            self.assertEqual(source.read_text(encoding="utf-8"), FLAG_DOC)

    def test_diff_reports_no_change_for_a_clean_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "box.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            code, out, _ = run(["diff", str(source)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("nothing would change", out)


class InitAndRulesTests(unittest.TestCase):
    def test_init_writes_a_loadable_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".writeup-scrub.toml"
            code, out, _ = run(["init", "--path", str(path)])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("wrote", out)
            tomllib.loads(path.read_text(encoding="utf-8"))

    def test_init_refuses_to_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".writeup-scrub.toml"
            path.write_text("# mine\n", encoding="utf-8")
            code, _, err = run(["init", "--path", str(path)])
            self.assertEqual(code, EXIT_USAGE)
            self.assertIn("already exists", err)
            self.assertEqual(path.read_text(encoding="utf-8"), "# mine\n")

    def test_init_force_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / ".writeup-scrub.toml"
            path.write_text("# mine\n", encoding="utf-8")
            code, _, _ = run(["init", "--path", str(path), "--force"])
            self.assertEqual(code, EXIT_OK)
            self.assertIn("[rules.WS001]", path.read_text(encoding="utf-8"))

    def test_rules_lists_every_rule(self):
        code, out, _ = run(["rules"])
        self.assertEqual(code, EXIT_OK)
        for rule_id in ("WS001", "WS002", "WS003", "WS004", "WS005", "WS006", "WS007"):
            self.assertIn(rule_id, out)

    def test_config_file_is_discovered_and_applied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".writeup-scrub.toml").write_text(
                "[rules.WS001]\nenabled = false\n", encoding="utf-8"
            )
            source = root / "box.md"
            source.write_text(FLAG_DOC, encoding="utf-8")
            code, _, _ = run(
                ["scan", str(source), "--config", str(root / ".writeup-scrub.toml")]
            )
            self.assertEqual(code, EXIT_OK)


class RetirementCliTests(unittest.TestCase):
    """The networked path is never exercised: no token is set in the test env."""

    def test_missing_token_aborts_before_processing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Blackfield.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            code, _, err = run(
                [
                    "scan",
                    str(source),
                    "--check-retired",
                    "--machine",
                    "Blackfield",
                    "--token-env",
                    "WRITEUP_SCRUB_TEST_ABSENT_TOKEN",
                ]
            )
            self.assertEqual(code, EXIT_RETIREMENT)
            self.assertIn("could not be completed", err)
            self.assertIn("refusing to assume", err)

    def test_retired_machine_lets_the_scan_proceed(self):
        payload = b'{"info": [{"name": "Blackfield"}]}'
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Blackfield.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            with mock.patch.dict(os.environ, {"HTB_TOKEN": "test-token"}), mock.patch(
                "writeup_scrub.platforms.base.urlopen_fetch",
                lambda url, headers, timeout: payload,
            ):
                code, out, err = run(["scan", str(source), "--check-retired"])
            self.assertEqual(code, EXIT_OK, err)
            self.assertIn("Blackfield is retired", out)
            self.assertIn("using 'Blackfield'", out, "machine name from filename")

    def test_active_machine_blocks_with_exit_three(self):
        payload = b'{"info": [{"name": "Forest"}]}'
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "BrandNewBox.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            with mock.patch.dict(os.environ, {"HTB_TOKEN": "test-token"}), mock.patch(
                "writeup_scrub.platforms.base.urlopen_fetch",
                lambda url, headers, timeout: payload,
            ):
                code, _, err = run(["scan", str(source), "--check-retired"])
            self.assertEqual(code, EXIT_RETIREMENT)
            self.assertIn("NOT in the htb retired list", err)
            self.assertIn("breaks the platform rules", err)

    def test_unreachable_api_blocks_rather_than_assuming_retired(self):
        def boom(url, headers, timeout):
            raise OSError("network is unreachable")

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Blackfield.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            with mock.patch.dict(os.environ, {"HTB_TOKEN": "test-token"}), mock.patch(
                "writeup_scrub.platforms.base.urlopen_fetch", boom
            ):
                code, _, err = run(["scan", str(source), "--check-retired"])
            self.assertEqual(code, EXIT_RETIREMENT)
            self.assertIn("could not be completed", err)
            self.assertIn("refusing to assume", err)

    def test_unknown_platform_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "box.md"
            source.write_text(CLEAN_DOC, encoding="utf-8")
            code, _, err = run(
                ["scan", str(source), "--check-retired", "--platform", "thm"]
            )
            self.assertEqual(code, EXIT_RETIREMENT)
            self.assertIn("unknown platform", err)


class FixtureSweepTests(unittest.TestCase):
    def test_every_positive_fixture_is_flagged(self):
        names = [
            "ws001_flags_positive.md",
            "ws002_secrets_positive.md",
            "ws003_paths_positive.md",
            "ws004_identifiers_positive.md",
            "ws006_notes_positive.md",
            "ws007_scratch_positive.md",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names:
                (root / name).write_text(fixture(name), encoding="utf-8")
            code, out, _ = run(["scan", str(root), "--fail-on", "info"])
            self.assertEqual(code, EXIT_GATE)
            for name in names:
                self.assertIn(name, out)

    def test_negative_fixtures_pass_the_critical_gate(self):
        names = [
            "ws001_hashes_negative.md",
            "ws002_secrets_negative.md",
            "ws003_paths_negative.md",
            "ws004_identifiers_negative.md",
            "ws007_scratch_negative.md",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in names:
                (root / name).write_text(fixture(name), encoding="utf-8")
            code, _, err = run(["scan", str(root), "--config", "/dev/null"])
            self.assertEqual(code, EXIT_OK, err)


if __name__ == "__main__":
    unittest.main()
