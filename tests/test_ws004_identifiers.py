"""WS004: the author's identifiers, not the target's."""

import unittest

from .support import fixture, redactions, run_rule


class EmailTests(unittest.TestCase):
    def test_personal_email_redacted(self):
        output, findings = run_rule("WS004", "mail me at rj.tester@gmail.com\n")
        self.assertEqual(output.strip(), "mail me at [REDACTED: email]")
        self.assertEqual(len(redactions(findings)), 1)
        self.assertEqual(findings[0].severity.value, "medium")

    def test_in_universe_htb_domain_preserved(self):
        output, findings = run_rule("WS004", "admin@target.htb\n")
        self.assertEqual(output.strip(), "admin@target.htb")
        self.assertEqual(findings, [])

    def test_dot_local_domain_preserved(self):
        output, _ = run_rule("WS004", "svc_backup@blackfield.local\n")
        self.assertIn("svc_backup@blackfield.local", output)

    def test_example_com_preserved(self):
        output, _ = run_rule("WS004", "postmaster@example.com\n")
        self.assertIn("postmaster@example.com", output)

    def test_subdomain_of_preserved_domain(self):
        output, _ = run_rule("WS004", "noreply@mail.example.com\n")
        self.assertIn("noreply@mail.example.com", output)

    def test_preserve_addresses_allowlist(self):
        output, findings = run_rule(
            "WS004",
            "contact me@handle.dev not me@gmail.com\n",
            preserve_addresses=["me@handle.dev"],
        )
        self.assertIn("me@handle.dev", output)
        self.assertNotIn("me@gmail.com", output)
        self.assertEqual(len(redactions(findings)), 1)

    def test_preserve_domains_is_configurable(self):
        output, _ = run_rule(
            "WS004", "user@corp.internal\n", preserve_domains=["corp.internal"]
        )
        self.assertIn("user@corp.internal", output)

    def test_impacket_user_at_host_is_not_an_email(self):
        text = "impacket-secretsdump blackfield.local/svc@10.10.10.192\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_ssh_public_key_comment_is_not_an_email(self):
        text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaQmRMUlNQ user@target\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_user_at_bare_ip_is_not_an_email(self):
        text = "ssh root@10.10.11.3 and scp x root@127.0.0.1:/tmp\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_email_detection_can_be_disabled(self):
        output, findings = run_rule("WS004", "rj.tester@gmail.com\n", detect_emails=False)
        self.assertIn("rj.tester@gmail.com", output)
        self.assertEqual(findings, [])


class PhoneTests(unittest.TestCase):
    def test_parenthesised_number(self):
        output, _ = run_rule("WS004", "call (555) 123-4567 now\n")
        self.assertEqual(output.strip(), "call [REDACTED: phone] now")

    def test_dotted_number(self):
        output, _ = run_rule("WS004", "fax 555.123.4567.\n")
        self.assertIn("[REDACTED: phone]", output)

    def test_dashed_number(self):
        output, _ = run_rule("WS004", "cell 555-123-4567\n")
        self.assertIn("[REDACTED: phone]", output)

    def test_international_number(self):
        output, _ = run_rule("WS004", "cell +1 555 987 6543\n")
        self.assertIn("[REDACTED: phone]", output)

    def test_international_number_at_end_of_sentence(self):
        output, _ = run_rule("WS004", "reached me on +1 555 987 6543.\n")
        self.assertIn("[REDACTED: phone]", output)
        self.assertTrue(output.strip().endswith("."))

    def test_ipv4_is_not_a_phone_number(self):
        text = "scanned 10.10.14.37 and 192.168.1.100\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_version_string_is_not_a_phone_number(self):
        text = "version 1.234.5678 build 12.34.56.78\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_mismatched_separators_are_not_a_phone_number(self):
        text = "ratio 100.200 3000 and 100 200 3000\n"
        output, findings = run_rule("WS004", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_phone_detection_can_be_disabled(self):
        output, findings = run_rule("WS004", "(555) 123-4567\n", detect_phones=False)
        self.assertIn("(555) 123-4567", output)
        self.assertEqual(findings, [])


class FixtureTests(unittest.TestCase):
    def test_positive_fixture(self):
        output, findings = run_rule("WS004", fixture("ws004_identifiers_positive.md"))
        self.assertNotIn("a.reporter.personal@gmail.com", output)
        self.assertNotIn("(555) 123-4567", output)
        self.assertNotIn("555.123.4567", output)
        self.assertNotIn("+1 555 987 6543", output)
        self.assertEqual(len(redactions(findings)), 4)

    def test_negative_fixture_untouched(self):
        source = fixture("ws004_identifiers_negative.md")
        output, findings = run_rule("WS004", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
