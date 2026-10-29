"""WS007: warnings only -- this rule must never edit the document."""

import unittest

from .support import fixture, redactions, run_rule, warnings


class ScratchContentTests(unittest.TestCase):
    def test_todo_warns_without_editing(self):
        source = "TODO: finish this section\n"
        output, findings = run_rule("WS007", source)
        self.assertEqual(output, source, "WS007 must not edit the document")
        self.assertEqual(len(warnings(findings)), 1)
        self.assertEqual(redactions(findings), [])
        self.assertEqual(findings[0].severity.value, "info")

    def test_fixme_and_xxx_and_hack(self):
        for marker in ("FIXME", "XXX", "HACK", "WIP"):
            _, findings = run_rule("WS007", f"{marker} something\n")
            self.assertTrue(warnings(findings), f"{marker} not reported")

    def test_markers_are_case_sensitive_words(self):
        _, findings = run_rule("WS007", "todos are tracked elsewhere\n")
        self.assertEqual(
            [f for f in warnings(findings) if "marker" in f.message], []
        )

    def test_markers_are_configurable(self):
        _, findings = run_rule("WS007", "REVIEWME later\n", markers=["REVIEWME"])
        self.assertTrue(warnings(findings))

    def test_discord_aside_warns(self):
        _, findings = run_rule("WS007", "I had to ask in discord about this\n")
        self.assertTrue(any("ask in discord" in f.message for f in findings))

    def test_hint_aside_warns(self):
        _, findings = run_rule("WS007", "got hint from a friend here\n")
        self.assertTrue(any("got hint from" in f.message for f in findings))

    def test_phrases_are_configurable(self):
        _, findings = run_rule("WS007", "my secret method\n", phrases=["secret method"])
        self.assertTrue(warnings(findings))

    def test_empty_section_warns(self):
        source = "# Title\n\n## Foothold\n\nreal content\n\n## Privesc\n\n## Loot\n\nmore\n"
        _, findings = run_rule("WS007", source)
        empty = [f for f in findings if "no content" in f.message]
        self.assertEqual(len(empty), 1)
        self.assertIn("Privesc", empty[0].message)

    def test_subsection_counts_as_content(self):
        source = "# Title\n\n## Parent\n\n### Child\n\ncontent here\n"
        _, findings = run_rule("WS007", source)
        self.assertEqual([f for f in findings if "no content" in f.message], [])

    def test_empty_section_warning_can_be_disabled(self):
        source = "# Title\n\n## Empty\n\n## Next\n\ncontent\n"
        _, findings = run_rule("WS007", source, warn_empty_sections=False)
        self.assertEqual([f for f in findings if "no content" in f.message], [])

    def test_heading_inside_a_fence_is_not_a_section(self):
        source = "# Title\n\n```\n# not a heading\n```\n"
        _, findings = run_rule("WS007", source)
        self.assertEqual([f for f in findings if "no content" in f.message], [])

    def test_positive_fixture(self):
        source = fixture("ws007_scratch_positive.md")
        output, findings = run_rule("WS007", source)
        self.assertEqual(output, source)
        self.assertGreaterEqual(len(warnings(findings)), 6)
        messages = " ".join(f.message for f in findings)
        self.assertIn("TODO", messages)
        self.assertIn("FIXME", messages)
        self.assertIn("XXX", messages)
        self.assertIn("ask in discord", messages)
        self.assertIn("no content", messages)

    def test_negative_fixture_is_silent(self):
        source = fixture("ws007_scratch_negative.md")
        output, findings = run_rule("WS007", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
