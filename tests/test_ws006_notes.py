"""WS006: Obsidian/Notion artefacts."""

import unittest

from .support import fixture, redactions, run_rule


class FrontmatterTests(unittest.TestCase):
    def test_listed_keys_removed_others_kept(self):
        source = (
            "---\ntitle: Blackfield\ntags: [htb, windows]\nstatus: draft\n"
            "date: 2026-02-14\n---\n\n# Blackfield\n"
        )
        output, findings = run_rule("WS006", source)
        self.assertIn("title: Blackfield", output)
        self.assertIn("date: 2026-02-14", output)
        self.assertNotIn("tags:", output)
        self.assertNotIn("status:", output)
        self.assertEqual(len(redactions(findings)), 2)

    def test_multiline_list_value_removed_entirely(self):
        source = "---\ntitle: X\naliases:\n  - A\n  - B\n---\n\nbody\n"
        output, _ = run_rule("WS006", source)
        self.assertNotIn("aliases", output)
        self.assertNotIn("- A", output)
        self.assertNotIn("- B", output)
        self.assertIn("title: X", output)

    def test_frontmatter_block_removed_when_empty(self):
        source = "---\ntags: [a]\nstatus: draft\n---\n\n# Title\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, "\n# Title\n")
        self.assertTrue(any("empty frontmatter" in f.message for f in findings))

    def test_empty_frontmatter_can_be_kept(self):
        source = "---\ntags: [a]\n---\n\n# Title\n"
        output, _ = run_rule("WS006", source, drop_empty_frontmatter=False)
        self.assertTrue(output.startswith("---\n---\n"))

    def test_drop_keys_are_configurable(self):
        source = "---\ntags: [a]\nsecret_note: x\n---\n\nbody\n"
        output, _ = run_rule("WS006", source, drop_frontmatter_keys=["secret_note"])
        self.assertIn("tags: [a]", output)
        self.assertNotIn("secret_note", output)

    def test_no_frontmatter_is_not_an_error(self):
        source = "# Title\n\nbody\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])

    def test_a_horizontal_rule_is_not_frontmatter(self):
        source = "# Title\n\n---\n\nbody\n"
        output, _ = run_rule("WS006", source)
        self.assertEqual(output, source)


class WikilinkTests(unittest.TestCase):
    def test_plain_wikilink_to_text(self):
        output, findings = run_rule("WS006", "see [[AS-REP Roasting]] here\n")
        self.assertEqual(output.strip(), "see AS-REP Roasting here")
        self.assertEqual(len(redactions(findings)), 1)

    def test_aliased_wikilink_uses_alias(self):
        output, _ = run_rule("WS006", "see [[Kerberos#Delegation|delegation]] here\n")
        self.assertEqual(output.strip(), "see delegation here")

    def test_embed_becomes_plain_text(self):
        output, _ = run_rule("WS006", "![[diagram.png]]\n")
        self.assertEqual(output.strip(), "diagram.png")

    def test_link_mode_produces_markdown_link(self):
        output, _ = run_rule("WS006", "see [[AS-REP Roasting]]\n", wikilink_mode="link")
        self.assertEqual(output.strip(), "see [AS-REP Roasting](AS-REP%20Roasting.md)")

    def test_link_mode_keeps_anchor(self):
        output, _ = run_rule(
            "WS006", "[[Kerberos#Delegation|notes]]\n", wikilink_mode="link"
        )
        self.assertEqual(output.strip(), "[notes](Kerberos.md#delegation)")

    def test_link_mode_embed_is_an_image(self):
        output, _ = run_rule("WS006", "![[diagram.png]]\n", wikilink_mode="link")
        self.assertEqual(output.strip(), "![diagram.png](diagram.png)")

    def test_link_mode_extension_is_configurable(self):
        output, _ = run_rule(
            "WS006", "[[Page]]\n", wikilink_mode="link", wikilink_extension=".html"
        )
        self.assertEqual(output.strip(), "[Page](Page.html)")

    def test_normal_markdown_link_untouched(self):
        source = "a [link](https://example.com/x) and `code`\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])


class CalloutTests(unittest.TestCase):
    def test_warning_callout_with_title(self):
        output, findings = run_rule(
            "WS006", "> [!warning] Careful\n> It locks accounts.\n"
        )
        self.assertEqual(
            output, "> [!WARNING]\n> **Careful**\n> It locks accounts.\n"
        )
        self.assertEqual(len(redactions(findings)), 1)

    def test_fold_marker_removed(self):
        output, _ = run_rule("WS006", "> [!tip]+ Faster\n> body\n")
        self.assertEqual(output, "> [!TIP]\n> **Faster**\n> body\n")

    def test_unmapped_type_falls_back_to_note(self):
        output, _ = run_rule("WS006", "> [!custom] Thing\n> body\n")
        self.assertIn("> [!NOTE]", output)

    def test_info_maps_to_note(self):
        output, _ = run_rule("WS006", "> [!info]\n> body\n")
        self.assertEqual(output, "> [!NOTE]\n> body\n")

    def test_danger_maps_to_caution(self):
        output, _ = run_rule("WS006", "> [!danger]\n> body\n")
        self.assertIn("[!CAUTION]", output)

    def test_already_github_flavoured_is_stable(self):
        source = "> [!NOTE]\n> body\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(redactions(findings), [])

    def test_callout_conversion_can_be_disabled(self):
        source = "> [!warning] Careful\n> body\n"
        output, _ = run_rule("WS006", source, convert_callouts=False)
        self.assertEqual(output, source)

    def test_plain_blockquote_untouched(self):
        source = "> just a quote\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])


class CommentTests(unittest.TestCase):
    def test_inline_comment_removed(self):
        output, findings = run_rule("WS006", "text %% private note %% more\n")
        self.assertEqual(output.strip(), "text  more")
        self.assertEqual(len(redactions(findings)), 1)

    def test_comment_block_removed(self):
        source = "before\n\n%%\nprivate\nlines\n%%\n\nafter\n"
        output, findings = run_rule("WS006", source)
        self.assertNotIn("private", output)
        self.assertIn("before", output)
        self.assertIn("after", output)
        block = [f for f in findings if "block" in f.message][0]
        self.assertEqual(block.extra["lines_removed"], 2)

    def test_unterminated_comment_block_is_left_alone(self):
        source = "before\n\n%%\nprivate\nmore\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])

    def test_percentages_are_not_comments(self):
        source = "50% done, 100% coverage\n"
        output, findings = run_rule("WS006", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])

    def test_comment_stripping_can_be_disabled(self):
        source = "text %% note %%\n"
        output, _ = run_rule("WS006", source, strip_comments=False)
        self.assertEqual(output, source)


class FixtureTests(unittest.TestCase):
    def test_positive_fixture(self):
        output, findings = run_rule("WS006", fixture("ws006_notes_positive.md"))
        self.assertNotIn("tags:", output)
        self.assertNotIn("status: draft", output)
        self.assertNotIn("aliases", output)
        self.assertNotIn("[[", output)
        self.assertNotIn("%%", output)
        self.assertNotIn("Private scratch block", output)
        self.assertIn("title: Blackfield", output)
        self.assertIn("> [!WARNING]", output)
        self.assertIn("> [!TIP]", output)
        self.assertGreaterEqual(len(redactions(findings)), 9)
        for finding in findings:
            self.assertEqual(finding.severity.value, "low")


if __name__ == "__main__":
    unittest.main()
