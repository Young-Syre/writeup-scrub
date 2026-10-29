"""The markdown hygiene pass."""

import unittest

from writeup_scrub.config import HYGIENE_DEFAULTS
from writeup_scrub.document import Document
from writeup_scrub.hygiene import Hygiene, sniff_language

from .support import fixture


def run_hygiene(text: str, **overrides):
    cfg = dict(HYGIENE_DEFAULTS)
    cfg.update(overrides)
    doc = Document.from_text(text, path="<hygiene>")
    findings = Hygiene().apply(doc, cfg)
    return doc.render(), findings


class FenceTests(unittest.TestCase):
    def test_unterminated_fence_is_closed(self):
        output, findings = run_hygiene("# T\n\n```bash\n$ id\n")
        self.assertTrue(output.rstrip().endswith("```"))
        self.assertEqual(len(Document.from_text(output).fences()), 1)
        self.assertTrue(Document.from_text(output).fences()[0].terminated)
        self.assertEqual([f.rule for f in findings if f.rule == "MD-FENCE"], ["MD-FENCE"])

    def test_terminated_fence_is_left_alone(self):
        source = "```bash\n$ id\n```\n"
        output, findings = run_hygiene(source)
        self.assertEqual(output, source)
        self.assertEqual([f for f in findings if f.rule == "MD-FENCE"], [])

    def test_fence_closing_can_be_disabled(self):
        output, _ = run_hygiene(
            "```\n$ id\n",
            close_unterminated_fences=False,
            infer_fence_language=False,
        )
        self.assertEqual(output, "```\n$ id\n")


class LanguageTests(unittest.TestCase):
    def test_bash_inferred(self):
        output, findings = run_hygiene("```\n$ nmap -sC 10.10.11.3\n```\n")
        self.assertTrue(output.startswith("```bash"))
        self.assertTrue(any(f.rule == "MD-LANG" for f in findings))

    def test_python_inferred(self):
        output, _ = run_hygiene("```\nimport os\ndef x():\n    pass\n```\n")
        self.assertTrue(output.startswith("```python"))

    def test_powershell_inferred(self):
        output, _ = run_hygiene("```\nPS C:\\> Get-ADUser -Filter *\n```\n")
        self.assertTrue(output.startswith("```powershell"))

    def test_sql_inferred(self):
        output, _ = run_hygiene("```\nSELECT user, pass FROM users\n```\n")
        self.assertTrue(output.startswith("```sql"))

    def test_http_inferred(self):
        output, _ = run_hygiene("```\nGET /admin HTTP/1.1\nHost: t.htb\n```\n")
        self.assertTrue(output.startswith("```http"))

    def test_json_inferred(self):
        output, _ = run_hygiene('```\n{"a": 1}\n```\n')
        self.assertTrue(output.startswith("```json"))

    def test_unknown_falls_back_to_default(self):
        output, _ = run_hygiene("```\njust some prose\n```\n")
        self.assertTrue(output.startswith("```text"))

    def test_existing_language_hint_is_respected(self):
        source = "```ruby\nputs 1\n```\n"
        output, findings = run_hygiene(source)
        self.assertEqual(output, source)
        self.assertEqual([f for f in findings if f.rule == "MD-LANG"], [])

    def test_empty_fence_gets_no_hint(self):
        source = "```\n\n```\n"
        output, _ = run_hygiene(source)
        self.assertEqual(output, source)

    def test_sniff_returns_none_for_prose(self):
        self.assertIsNone(sniff_language(["nothing technical here"]))

    def test_inference_can_be_disabled(self):
        output, _ = run_hygiene("```\n$ id\n```\n", infer_fence_language=False)
        self.assertTrue(output.startswith("```\n"))


class HeadingTests(unittest.TestCase):
    def test_single_h2_document_is_promoted(self):
        output, findings = run_hygiene("## Title\n\nbody\n\n### Sub\n\nmore\n")
        self.assertTrue(output.startswith("# Title"))
        self.assertIn("## Sub", output)
        self.assertEqual(len([f for f in findings if f.rule == "MD-HEADING"]), 2)

    def test_extra_h1_is_demoted(self):
        output, _ = run_hygiene("# First\n\nbody\n\n# Second\n\nbody\n")
        self.assertIn("# First", output)
        self.assertIn("## Second", output)
        self.assertEqual(output.count("\n# "), 0)

    def test_already_correct_headings_are_untouched(self):
        source = "# Title\n\n## A\n\nbody\n\n## B\n\nbody\n"
        output, findings = run_hygiene(source)
        self.assertEqual(output, source)
        self.assertEqual([f for f in findings if f.rule == "MD-HEADING"], [])

    def test_exactly_one_h1_after_normalisation(self):
        output, _ = run_hygiene("### A\n\nx\n\n### B\n\ny\n\n#### C\n\nz\n")
        lines = [line for line in output.splitlines() if line.startswith("#")]
        self.assertEqual(sum(1 for line in lines if line.startswith("# ")), 1)

    def test_heading_inside_fence_is_not_a_heading(self):
        source = "# Title\n\n```\n# a comment\n```\n"
        output, findings = run_hygiene(source)
        self.assertIn("# a comment", output)
        self.assertEqual([f for f in findings if f.rule == "MD-HEADING"], [])

    def test_normalisation_can_be_disabled(self):
        source = "## Only\n\nbody\n"
        output, _ = run_hygiene(source, normalise_headings=False)
        self.assertEqual(output, source)


class WhitespaceTests(unittest.TestCase):
    def test_trailing_whitespace_stripped(self):
        output, findings = run_hygiene("text with spaces   \n")
        self.assertEqual(output, "text with spaces\n")
        self.assertTrue(any(f.rule == "MD-WS" for f in findings))

    def test_code_content_is_byte_preserved(self):
        source = "```\nindented   \n```\n"
        output, _ = run_hygiene(source)
        self.assertIn("indented   ", output)

    def test_blank_runs_collapsed(self):
        output, findings = run_hygiene("a\n\n\n\n\nb\n")
        self.assertEqual(output, "a\n\nb\n")
        self.assertEqual(len([f for f in findings if f.rule == "MD-BLANK"]), 3)

    def test_blank_lines_inside_fence_are_kept(self):
        source = "```\na\n\n\n\nb\n```\n"
        output, _ = run_hygiene(source, infer_fence_language=False)
        self.assertEqual(output, source)

    def test_blank_limit_is_configurable(self):
        output, _ = run_hygiene("a\n\n\n\nb\n", max_consecutive_blank_lines=2)
        self.assertEqual(output, "a\n\n\nb\n")

    def test_hygiene_findings_are_informational(self):
        _, findings = run_hygiene("## T   \n\n\n\nbody\n")
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.kind, "hygiene")
            self.assertEqual(finding.severity.value, "info")


class MessyFixtureTests(unittest.TestCase):
    def test_messy_fixture_becomes_clean(self):
        output, findings = run_hygiene(fixture("hygiene_messy.md"))
        document = Document.from_text(output)
        self.assertTrue(all(fence.terminated for fence in document.fences()))
        self.assertEqual(
            sum(1 for line in output.splitlines() if line.startswith("# ")), 1
        )
        self.assertNotIn("   \n", output)
        self.assertNotIn("\n\n\n", output)
        for language in ("```bash", "```python", "```http", "```sql", "```json"):
            self.assertIn(language, output)
        self.assertTrue(findings)


if __name__ == "__main__":
    unittest.main()
