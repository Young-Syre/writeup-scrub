"""End-to-end pipeline behaviour and the JSON manifest."""

import json
import unittest

from writeup_scrub.config import Config
from writeup_scrub.findings import Severity, fingerprint, meets_threshold
from writeup_scrub.pipeline import gate_failures, process_text
from writeup_scrub.report import build_manifest

from .support import fixture


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.rules["WS005"]["strip_cidrs"] = ["10.10.14.0/24"]
        self.config.rules["WS003"]["users"] = ["jordan"]
        self.source = fixture("writeup_end_to_end.md")
        self.result = process_text(self.source, "writeups/Blackfield.md", self.config)

    def test_flags_are_gone(self):
        self.assertNotIn("0123456789abcdef0123456789abcdef", self.result.output)
        self.assertNotIn("fedcba9876543210fedcba9876543210", self.result.output)

    def test_hashes_survive(self):
        self.assertIn("9658d1d1dcd9250115e2205d9f48400d", self.result.output)
        self.assertIn("aad3b435b51404eeaad3b435b51404ee", self.result.output)
        self.assertIn("8846f7eaee8fb117ad06bdd830b7586c", self.result.output)

    def test_secret_is_gone(self):
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", self.result.output)

    def test_personal_email_gone_target_addresses_untouched(self):
        self.assertNotIn("a.reporter.personal@gmail.com", self.result.output)

    def test_operator_path_and_address_rewritten(self):
        self.assertNotIn("/home/jordan", self.result.output)
        self.assertIn("/home/operator/htb/blackfield", self.result.output)
        self.assertNotIn("10.10.14.37", self.result.output)
        self.assertIn("10.10.10.192", self.result.output, "target address was stripped")

    def test_note_artefacts_removed(self):
        self.assertNotIn("tags:", self.result.output)
        self.assertNotIn("[[", self.result.output)

    def test_hygiene_normalised_headings_and_languages(self):
        headings = [
            line for line in self.result.output.splitlines() if line.startswith("#")
        ]
        self.assertEqual(headings[0], "# Blackfield - 10.10.10.192")
        self.assertEqual(sum(1 for line in headings if line.startswith("# ")), 1)
        self.assertIn("```bash", self.result.output)

    def test_todo_is_reported_but_kept(self):
        self.assertIn("TODO: add the BloodHound screenshots.", self.result.output)
        self.assertTrue(
            any(f.rule == "WS007" and f.kind == "warning" for f in self.result.findings)
        )

    def test_findings_are_attributed_to_the_file(self):
        for finding in self.result.findings:
            self.assertEqual(finding.path, "writeups/Blackfield.md")
            self.assertGreater(finding.line, 0)

    def test_findings_are_sorted_by_line(self):
        lines = [f.line for f in self.result.findings]
        self.assertEqual(lines, sorted(lines))

    def test_result_reports_a_change(self):
        self.assertTrue(self.result.changed)
        self.assertNotEqual(self.result.output, self.source)

    def test_redaction_context_shows_the_sanitised_line(self):
        flag_findings = [
            f for f in self.result.findings if f.rule == "WS001" and f.is_redaction
        ]
        self.assertTrue(flag_findings)
        for finding in flag_findings:
            self.assertIsNotNone(finding.context)
            self.assertIn("[REDACTED: platform flag]", finding.context)
            self.assertNotIn("0123456789ab", finding.context)


class GateTests(unittest.TestCase):
    def test_critical_finding_fails_the_default_gate(self):
        config = Config()
        result = process_text("User flag: " + "a" * 32 + "\n", "t.md", config)
        failures = gate_failures([result], Severity.CRITICAL)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].rule, "WS001")

    def test_medium_finding_does_not_fail_the_critical_gate(self):
        config = Config()
        config.rules["WS003"]["users"] = ["jordan"]
        result = process_text("cd /home/jordan/x\n", "t.md", config)
        self.assertEqual(gate_failures([result], Severity.CRITICAL), [])
        self.assertEqual(len(gate_failures([result], Severity.MEDIUM)), 1)

    def test_hygiene_never_fails_a_gate(self):
        config = Config()
        result = process_text("## Only heading   \n\nbody\n", "t.md", config)
        self.assertTrue(result.findings)
        self.assertEqual(gate_failures([result], Severity.INFO), [])

    def test_threshold_ordering(self):
        self.assertTrue(meets_threshold(Severity.CRITICAL, Severity.MEDIUM))
        self.assertFalse(meets_threshold(Severity.LOW, Severity.HIGH))
        self.assertTrue(meets_threshold(Severity.INFO, Severity.INFO))

    def test_clean_document_produces_no_findings(self):
        config = Config()
        result = process_text(fixture("ws007_scratch_negative.md"), "t.md", config)
        self.assertEqual(result.findings, [])
        self.assertFalse(result.changed)


class CrossRuleFalsePositiveTests(unittest.TestCase):
    """A negative fixture must stay silent with *every* rule enabled.

    Rules are independent, so a pattern in one can fire on another's fixture --
    an email regex matching `svc@10.10.10.192` in an impacket command, for
    instance. This test is the regression guard for that class of bug.
    """

    def assert_clean(self, name: str, **config_overrides):
        config = Config()
        config.hygiene["enabled"] = False
        for rule_id, settings in config_overrides.items():
            config.rules[rule_id].update(settings)
        source = fixture(name)
        result = process_text(source, name, config)
        self.assertEqual(
            [f"{f.rule}:{f.line}:{f.message}" for f in result.findings],
            [],
            f"{name} produced findings with every rule enabled",
        )
        self.assertEqual(result.output, source)

    def test_hash_fixture_is_clean_under_every_rule(self):
        self.assert_clean("ws001_hashes_negative.md")

    def test_secrets_fixture_is_clean_under_every_rule(self):
        self.assert_clean("ws002_secrets_negative.md")

    def test_identifiers_fixture_is_clean_under_every_rule(self):
        self.assert_clean("ws004_identifiers_negative.md")

    def test_scratch_fixture_is_clean_under_every_rule(self):
        self.assert_clean("ws007_scratch_negative.md")

    def test_paths_fixture_is_clean_when_users_are_scoped(self):
        self.assert_clean("ws003_paths_negative.md", WS003={"users": ["jordan"]})


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.result = process_text(
            "User flag: 0123456789abcdef0123456789abcdef\n", "t.md", self.config
        )

    def test_manifest_shape(self):
        manifest = build_manifest([self.result], mode="scan", config=self.config)
        self.assertEqual(manifest["tool"], "writeup-scrub")
        self.assertEqual(manifest["mode"], "scan")
        self.assertEqual(manifest["summary"]["files"], 1)
        self.assertEqual(manifest["summary"]["redactions"], 1)
        self.assertEqual(manifest["summary"]["by_rule"]["WS001"], 1)
        self.assertEqual(manifest["summary"]["by_severity"]["critical"], 1)
        self.assertEqual(manifest["files"][0]["path"], "t.md")
        self.assertTrue(manifest["files"][0]["changed"])

    def test_manifest_is_json_serialisable(self):
        manifest = build_manifest([self.result], mode="scan", config=self.config)
        json.loads(json.dumps(manifest))

    def test_manifest_withholds_plaintext_by_default(self):
        manifest = build_manifest([self.result], mode="scan", config=self.config)
        blob = json.dumps(manifest)
        self.assertNotIn("0123456789abcdef0123456789abcdef", blob)
        finding = manifest["files"][0]["findings"][0]
        self.assertEqual(
            finding["original_fingerprint"],
            fingerprint("0123456789abcdef0123456789abcdef"),
        )
        self.assertEqual(finding["original_length"], 32)
        self.assertFalse(manifest["plaintext_included"])

    def test_manifest_can_reveal_plaintext_on_request(self):
        manifest = build_manifest(
            [self.result], mode="scan", config=self.config, reveal=True
        )
        blob = json.dumps(manifest)
        self.assertIn("0123456789abcdef0123456789abcdef", blob)
        self.assertTrue(manifest["plaintext_included"])

    def test_manifest_records_enabled_rules(self):
        config = Config()
        config.apply_toggles([], ["WS006", "WS007"])
        result = process_text("x\n", "t.md", config)
        manifest = build_manifest([result], mode="scan", config=config)
        self.assertNotIn("WS006", manifest["rules_enabled"])
        self.assertIn("WS001", manifest["rules_enabled"])


if __name__ == "__main__":
    unittest.main()


class InvisibleCharacterTests(unittest.TestCase):
    """Zero-width characters are stripped before any rule looks at the text.

    A U+200B in the middle of a flag renders as the whole flag but reads to a
    regex as two short hex runs, so the value would otherwise publish intact.
    """

    HEX = "8846f7eaee8fb117ad06bdd830b7586c"

    def _run(self, text: str):
        return process_text(text, "t.md", Config())

    def test_zero_width_space_does_not_hide_a_flag(self):
        split = self.HEX[:16] + "​" + self.HEX[16:]
        result = self._run(f"User flag: {split}\n")
        self.assertNotIn(self.HEX, result.output)
        self.assertNotIn("​", result.output)
        self.assertIn("[REDACTED: platform flag]", result.output)

    def test_bidi_override_does_not_hide_a_braced_flag(self):
        result = self._run("HTB{re‮al}\n")
        self.assertNotIn("‮", result.output)
        self.assertIn("[REDACTED: platform flag]", result.output)

    def test_stripping_happens_inside_code_fences_too(self):
        split = self.HEX[:16] + "​" + self.HEX[16:]
        result = self._run(f"```\n$ cat user.txt\n{split}\n```\n")
        self.assertNotIn(self.HEX, result.output)
        self.assertIn("[REDACTED: platform flag]", result.output)

    def test_a_leading_byte_order_mark_is_left_alone(self):
        result = self._run("﻿# Machine\n")
        self.assertTrue(result.output.startswith("﻿"))
        self.assertEqual([f for f in result.findings if f.rule == "MD-ZW"], [])

    def test_the_strip_is_reported_as_a_hygiene_change(self):
        result = self._run("a​b\n")
        hygiene = [f for f in result.findings if f.rule == "MD-ZW"]
        self.assertEqual(len(hygiene), 1)
        self.assertEqual(hygiene[0].kind, "hygiene")
        self.assertIn("zero-width", hygiene[0].message)
