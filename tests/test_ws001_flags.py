"""WS001: the flag-versus-hash distinction, tested from both directions.

This is the rule that decides whether the tool is usable. A false negative
publishes a flag; a false positive destroys the technical content of a
retired-machine writeup. Both failures are tested explicitly.
"""

import unittest

from writeup_scrub.config import RULE_DEFAULTS

from .support import fixture, redactions, run_rule, warnings

MARKER = RULE_DEFAULTS["WS001"]["marker"]
HEX = "8846f7eaee8fb117ad06bdd830b7586c"


class FlagsRedactedTests(unittest.TestCase):
    """Positive direction: a 32-hex string in flag context must be redacted."""

    def assert_redacted(self, text: str) -> None:
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn(MARKER, output, f"not redacted: {text!r}")
        self.assertNotIn(HEX, output)
        self.assertTrue(redactions(findings))

    def test_user_flag_field(self):
        self.assert_redacted(f"User flag: {HEX}")

    def test_root_flag_field(self):
        self.assert_redacted(f"Root flag: {HEX}")

    def test_snake_case_field(self):
        self.assert_redacted(f"user_flag: {HEX}")

    def test_kebab_case_field(self):
        self.assert_redacted(f"root-flag = {HEX}")

    def test_flag_word_before_hex(self):
        self.assert_redacted(f"The flag is {HEX}")

    def test_flag_word_after_hex(self):
        self.assert_redacted(f"{HEX} was the user flag")

    def test_user_txt_mention(self):
        self.assert_redacted(f"user.txt contained {HEX}")

    def test_flag_in_code_fence_after_cat_command(self):
        text = f"```\n$ cat /root/root.txt\n{HEX}\n```"
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn(MARKER, output)
        self.assertEqual(len(redactions(findings)), 1)

    def test_flag_in_code_fence_after_prose_introduction(self):
        text = f"The root flag:\n\n```\n{HEX}\n```"
        output, _ = run_rule("WS001", text + "\n")
        self.assertIn(MARKER, output)

    def test_flag_submission_command(self):
        self.assert_redacted(f"$ htb submit --flag {HEX}")

    def test_braced_htb_flag(self):
        output, findings = run_rule("WS001", "Got HTB{not_a_real_flag}\n")
        self.assertEqual(output.strip(), f"Got {MARKER}")
        self.assertEqual(len(redactions(findings)), 1)

    def test_braced_ctf_flag(self):
        output, _ = run_rule("WS001", "flag{also_fake}\n")
        self.assertEqual(output.strip(), MARKER)

    def test_braced_flags_can_be_disabled(self):
        output, findings = run_rule(
            "WS001", "HTB{fake}\n", redact_braced_flags=False
        )
        self.assertEqual(output.strip(), "HTB{fake}")
        self.assertEqual(redactions(findings), [])

    def test_fixture_redacts_every_flag(self):
        output, findings = run_rule("WS001", fixture("ws001_flags_positive.md"))
        self.assertEqual(len(redactions(findings)), 9)
        for leaked in (
            "1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d",
            "5e6f70815e6f70815e6f70815e6f7081",
            "11112222333344445555666677778888",
            "88887777666655554444333322221111",
            "aaaa1111bbbb2222cccc3333dddd4444",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "0f0f0f0f1e1e1e1e2d2d2d2d3c3c3c3c",
            "HTB{a_fake_flag_for_testing}",
            "flag{another_fake_one}",
        ):
            self.assertNotIn(leaked, output, f"{leaked} survived")

    def test_every_finding_is_critical(self):
        _, findings = run_rule("WS001", fixture("ws001_flags_positive.md"))
        for finding in redactions(findings):
            self.assertEqual(finding.severity.value, "critical")
            self.assertEqual(finding.rule, "WS001")
            self.assertGreater(finding.line, 0)


class HashesPreservedTests(unittest.TestCase):
    """Negative direction: hashes are technical content and must survive."""

    def assert_preserved(self, text: str, value: str = HEX) -> None:
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn(value, output, f"wrongly redacted: {text!r}")
        self.assertEqual(redactions(findings), [], f"wrongly redacted: {text!r}")

    def test_ntlm_hash_label(self):
        self.assert_preserved(f"NTLM hash: {HEX}")

    def test_nt_hash_label(self):
        self.assert_preserved(f"NT hash: {HEX}")

    def test_md5sum_label(self):
        self.assert_preserved(f"md5sum output: {HEX}")

    def test_checksum_label(self):
        self.assert_preserved(f"checksum {HEX}")

    def test_hash_after_hex(self):
        self.assert_preserved(f"{HEX} is the NTLM hash")

    def test_secretsdump_line(self):
        line = f"Administrator:500:aad3b435b51404eeaad3b435b51404ee:{HEX}:::"
        self.assert_preserved(line)

    def test_nearest_label_wins_hash_closer(self):
        self.assert_preserved(f"I got the user flag after cracking the NTLM hash {HEX}")

    def test_md5sum_command_in_fence(self):
        text = f"```\n$ md5sum image.iso\n{HEX}  image.iso\n```"
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn(HEX, output)
        self.assertEqual(redactions(findings), [])

    def test_hashcat_command_in_fence(self):
        text = f"```\n$ hashcat -m 1000 hashes.txt rockyou.txt\n{HEX}:Password1\n```"
        output, _ = run_rule("WS001", text + "\n")
        self.assertIn(HEX, output)

    def test_empty_lm_hash_never_redacted(self):
        text = "User flag: aad3b435b51404eeaad3b435b51404ee"
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn("aad3b435b51404eeaad3b435b51404ee", output)
        self.assertEqual(redactions(findings), [])

    def test_empty_nt_hash_never_redacted(self):
        output, _ = run_rule("WS001", "flag 31d6cfe0d16ae931b73c59d7e0c089c0\n")
        self.assertIn("31d6cfe0d16ae931b73c59d7e0c089c0", output)

    def test_sha1_digest_untouched(self):
        self.assert_preserved(
            "sha1: 8846f7eaee8fb117ad06bdd830b7586cab12cd34",
            "8846f7eaee8fb117ad06bdd830b7586cab12cd34",
        )

    def test_uuid_with_dashes_untouched(self):
        value = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        self.assert_preserved(f"objectGUID: {value}", value)

    def test_etag_label(self):
        self.assert_preserved(f"ETag: {HEX}")

    def test_context_does_not_cross_an_earlier_code_block(self):
        text = (
            "The root flag:\n\n```\n1234567890abcdef1234567890abcdef\n```\n\n"
            f"```\n{HEX}\n```"
        )
        output, findings = run_rule("WS001", text + "\n")
        self.assertIn(HEX, output, "context leaked across a code block")
        self.assertEqual(len(redactions(findings)), 1)

    def test_fixture_preserves_every_hash(self):
        output, findings = run_rule("WS001", fixture("ws001_hashes_negative.md"))
        self.assertEqual(
            redactions(findings), [], "a hash was redacted in the negative fixture"
        )
        for preserved in (
            "8846f7eaee8fb117ad06bdd830b7586c",
            "9658d1d1dcd9250115e2205d9f48400d",
            "aad3b435b51404eeaad3b435b51404ee",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "c4ca4238a0b923820dcc509a6f75849b",
            "686897696a7c876b7e000000000000aa",
            "d41d8cd98f00b204e9800998ecf8427e",
            "8846f7eaee8fb117ad06bdd830b7586cab12cd34",
        ):
            self.assertIn(preserved, output, f"{preserved} was destroyed")


class AmbiguousHexTests(unittest.TestCase):
    """An unlabelled bare hex string is a judgement call, so it warns."""

    def test_bare_hex_alone_warns_but_is_kept(self):
        output, findings = run_rule("WS001", f"```\n{HEX}\n```\n")
        self.assertIn(HEX, output)
        self.assertEqual(redactions(findings), [])
        self.assertEqual(len(warnings(findings)), 1)
        self.assertIn("review it by hand", warnings(findings)[0].message)

    def test_bare_hex_can_be_redacted_by_config(self):
        output, findings = run_rule("WS001", f"```\n{HEX}\n```\n", redact_bare_hex=True)
        self.assertIn(MARKER, output)
        self.assertEqual(len(redactions(findings)), 1)

    def test_bare_hex_warning_can_be_silenced(self):
        _, findings = run_rule("WS001", f"```\n{HEX}\n```\n", warn_on_bare_hex=False)
        self.assertEqual(findings, [])

    def test_hex_with_filename_is_not_bare(self):
        output, findings = run_rule("WS001", f"{HEX}  ubuntu.iso\n")
        self.assertIn(HEX, output)
        self.assertEqual(findings, [])

    def test_extra_flag_keyword_is_honoured(self):
        output, _ = run_rule(
            "WS001", f"pwn3d marker {HEX}\n", extra_flag_keywords=["pwn3d"]
        )
        self.assertIn(MARKER, output)

    def test_extra_hash_keyword_is_honoured(self):
        output, _ = run_rule(
            "WS001", f"flag? no: pbkdf2 {HEX}\n", extra_hash_keywords=["pbkdf2"]
        )
        self.assertIn(HEX, output)


if __name__ == "__main__":
    unittest.main()


class BracedFlagCaseTests(unittest.TestCase):
    """Platforms are inconsistent about case; writeups are worse.

    A THM or picoCTF flag is words rather than hex, so there is no second line
    of defence: if the braced pattern misses one, it publishes.
    """

    def test_every_case_variant_is_redacted(self):
        for value in (
            "HTB{real_answer}",
            "htb{real_answer}",
            "Htb{real_answer}",
            "THM{real_answer}",
            "thm{this_is_the_real_answer}",
            "Thm{real_answer}",
            "FLAG{real_answer}",
            "flag{real_answer}",
            "Flag{real_answer}",
            "CTF{real_answer}",
            "ctf{real_answer}",
            "PICOCTF{real_answer}",
            "picoCTF{real_answer}",
            "pico{real_answer}",
            "KEY{real_answer}",
            "Key{real_answer}",
        ):
            with self.subTest(value=value):
                output, findings = run_rule("WS001", f"The flag was {value}\n")
                self.assertNotIn(value, output)
                self.assertIn(MARKER, output)
                self.assertEqual(len(redactions(findings)), 1)

    def test_a_word_ending_in_a_prefix_is_not_a_flag(self):
        for value in ("nothtb{x}", "unflag{x}", "HTB{}"):
            with self.subTest(value=value):
                output, findings = run_rule("WS001", value + "\n")
                self.assertIn(value, output)
                self.assertEqual(redactions(findings), [])


class UnlabelledHexWarningTests(unittest.TestCase):
    """The warning is about the value, not about where on the line it sits."""

    def test_hex_in_running_text_warns(self):
        for line in (
            f"Then I pasted {HEX} into the box.",
            f"Wrote it to /tmp/{HEX}",
            f"I saved it as {HEX}.txt in my notes",
        ):
            with self.subTest(line=line):
                output, findings = run_rule("WS001", line + "\n")
                self.assertIn(HEX, output, "warning only, never a redaction")
                self.assertEqual(redactions(findings), [])
                self.assertEqual(len(warnings(findings)), 1)
                self.assertIn("in running text", warnings(findings)[0].message)

    def test_redact_bare_hex_stays_scoped_to_a_line_of_its_own(self):
        line = f"Then I pasted {HEX} into the box.\n"
        output, findings = run_rule("WS001", line, redact_bare_hex=True)
        self.assertIn(HEX, output, "a hex string in prose is usually a hash")
        self.assertEqual(redactions(findings), [])

    def test_a_checksum_line_is_neither_redacted_nor_warned_about(self):
        for line in (f"{HEX}  ubuntu.iso", f"{HEX} *ubuntu.iso"):
            with self.subTest(line=line):
                output, findings = run_rule("WS001", line + "\n")
                self.assertIn(HEX, output)
                self.assertEqual(findings, [])
