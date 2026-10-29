"""WS002: live credentials, by prefix shape."""

import unittest

from .support import fixture, redactions, run_rule, warnings

MARKER = "[REDACTED: secret]"


def twilio_sk() -> str:
    """Assemble a Twilio-shaped SID at runtime.

    The pattern is SK followed by exactly 32 hex characters, so it cannot be
    shortened without failing to exercise the rule. Building it from fragments
    keeps a complete secret-shaped literal out of the source tree, which is what
    push-protection scanners (correctly) object to.
    """
    return "SK" + ("0123456789abcdef" * 2)


class SecretsPositiveTests(unittest.TestCase):
    def assert_redacted(self, text: str, secret: str) -> None:
        output, findings = run_rule("WS002", text + "\n")
        self.assertNotIn(secret, output, f"{secret} survived")
        self.assertIn(MARKER, output)
        self.assertTrue(redactions(findings))
        self.assertEqual(redactions(findings)[0].severity.value, "critical")

    def test_aws_access_key(self):
        self.assert_redacted("key=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE")

    def test_aws_session_key(self):
        self.assert_redacted("key=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE")

    def test_google_api_key(self):
        value = "AIzaEXAMPLEFAKEKEY000000000000000000000"
        self.assert_redacted(f"GOOGLE={value}", value)

    def test_stripe_live_key(self):
        value = "sk_live_EXAMPLEFAKE0"
        self.assert_redacted(f"STRIPE={value}", value)

    def test_stripe_restricted_key(self):
        value = "sk_live_EXAMPLEFAKE0"
        self.assert_redacted(f"STRIPE={value}", value)

    def test_github_classic_token(self):
        value = "ghp_EXAMPLEFAKETOKEN0000"
        self.assert_redacted(f"GITHUB={value}", value)

    def test_github_fine_grained_pat(self):
        value = "github_pat_EXAMPLE_FAKE_TOKEN00"
        self.assert_redacted(f"PAT={value}", value)

    def test_slack_bot_token(self):
        value = "xoxb-EXAMPLE-FAKE-TOKEN"
        self.assert_redacted(f"SLACK={value}", value)

    def test_sendgrid_key(self):
        value = "SG.EXAMPLE_FAKE_KEY_0.EXAMPLE_FAKE_KEY_1"
        self.assert_redacted(f"SENDGRID={value}", value)

    def test_openai_key(self):
        value = "sk-EXAMPLE_FAKE_OPENAI_000"
        self.assert_redacted(f"OPENAI={value}", value)

    def test_twilio_key(self):
        value = twilio_sk()
        self.assert_redacted(f"TWILIO={value}", value)

    def test_jwt(self):
        value = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXkk"
        )
        self.assert_redacted(f"Authorization: Bearer {value}", value)

    def test_jwt_detection_can_be_disabled(self):
        value = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXkk"
        )
        output, findings = run_rule("WS002", value + "\n", detect_jwts=False)
        self.assertIn(value, output)
        self.assertEqual(redactions(findings), [])

    def test_private_key_body_replaced_banners_kept(self):
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
            "AAAAMwAAAAtzc2gtZWQyNTUxOQAAACBaQmRMUlNQbEt\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        output, findings = run_rule("WS002", text)
        self.assertIn("-----BEGIN OPENSSH PRIVATE KEY-----", output)
        self.assertIn("-----END OPENSSH PRIVATE KEY-----", output)
        self.assertIn("[REDACTED: private key material]", output)
        self.assertNotIn("b3BlbnNzaC1rZXktdjEA", output)
        self.assertEqual(findings[0].extra["lines_removed"], 2)

    def test_private_key_detection_can_be_disabled(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        output, findings = run_rule("WS002", text, detect_private_keys=False)
        self.assertIn("MIIEpAIBAAKCAQEA", output)
        self.assertEqual(findings, [])

    def test_session_cookie_opt_in(self):
        text = "Cookie: PHPSESSID=a1b2c3d4e5f6g7h8i9j0\n"
        kept, kept_findings = run_rule("WS002", text)
        self.assertIn("a1b2c3d4e5f6g7h8i9j0", kept)
        self.assertEqual(kept_findings, [])
        stripped, stripped_findings = run_rule(
            "WS002", text, detect_session_cookies=True
        )
        self.assertNotIn("a1b2c3d4e5f6g7h8i9j0", stripped)
        self.assertIn("PHPSESSID=", stripped, "cookie name should survive")
        self.assertTrue(stripped_findings)

    def test_pattern_can_be_disabled_by_name(self):
        output, _ = run_rule(
            "WS002", "key=AKIAIOSFODNN7EXAMPLE\n", disabled_patterns=["aws_access_key"]
        )
        self.assertIn("AKIAIOSFODNN7EXAMPLE", output)

    def test_fixture_leaves_no_secret_behind(self):
        corpus = fixture("ws002_secrets_positive.md").replace(
            "__TWILIO_SK_PLACEHOLDER__", twilio_sk()
        )
        output, findings = run_rule("WS002", corpus)
        self.assertGreaterEqual(len(redactions(findings)), 12)
        for secret in (
            "AKIAIOSFODNN7EXAMPLE",
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaEXAMPLEFAKEKEY000000000000000000000",
            "sk_live_EXAMPLEFAKE0",
            "ghp_EXAMPLEFAKETOKEN0000",
            "github_pat_EXAMPLE_FAKE_TOKEN00",
            "xoxb-EXAMPLE-FAKE-TOKEN",
            "SG.AbCdEfGhIjKlMnOpQrStUv.",
            "sk-EXAMPLE_FAKE_OPENAI_000",
            twilio_sk(),
            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXkk",
            "b3BlbnNzaC1rZXktdjEA",
        ):
            self.assertNotIn(secret, output, f"{secret} survived")


class SecretsNegativeTests(unittest.TestCase):
    def test_negative_fixture_is_untouched(self):
        source = fixture("ws002_secrets_negative.md")
        output, findings = run_rule("WS002", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])

    def test_test_mode_stripe_key_survives(self):
        output, _ = run_rule("WS002", "sk_test_EXAMPLE_NOT_A_REAL_KEY\n")
        self.assertIn("sk_test_EXAMPLE_NOT_A_REAL_KEY", output)

    def test_public_key_survives(self):
        text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaQmRMUlNQbEtmU3BLZ1pF user@target\n"
        output, findings = run_rule("WS002", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_certificate_body_survives(self):
        text = (
            "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKS0yiqKk2gUMA0GCSqGSIb\n"
            "-----END CERTIFICATE-----\n"
        )
        output, findings = run_rule("WS002", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()


class TruncatedPrivateKeyTests(unittest.TestCase):
    """A BEGIN banner with no END banner must not eat the rest of the writeup.

    Pasting the first line of a key to show it was unencrypted is an ordinary
    thing to do in a writeup. Scanning forward to a banner that never arrives
    once deleted everything after it, which with ``--in-place`` is the source.
    """

    PROSE = (
        "# Machine\n"
        "\n"
        "I pulled the key off the box:\n"
        "\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "\n"
        "(truncated for the writeup)\n"
        "\n"
        "## Privilege escalation\n"
        "\n"
        "The cron job ran a world-writable script.\n"
    )

    def test_banner_in_prose_changes_nothing_and_warns(self):
        output, findings = run_rule("WS002", self.PROSE)
        self.assertEqual(output, self.PROSE, "the writeup must survive intact")
        self.assertEqual(redactions(findings), [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "warning")
        self.assertIn("no key body", findings[0].message)

    def test_real_body_without_end_banner_is_still_redacted(self):
        body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAA"
        text = (
            "# Machine\n"
            "\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{body}\n"
            "\n"
            "## Privilege escalation\n"
            "\n"
            "The cron job ran a world-writable script.\n"
        )
        output, findings = run_rule("WS002", text)
        self.assertNotIn(body, output)
        self.assertIn("[REDACTED: private key material]", output)
        self.assertIn("## Privilege escalation", output)
        self.assertIn("The cron job ran a world-writable script.", output)
        self.assertEqual(len(redactions(findings)), 1)
        self.assertIn("no END banner found", redactions(findings)[0].message)

    def test_rfc1421_headers_and_their_blank_line_are_redacted(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,F8E7D6C5B4A3928170615243\n"
            "\n"
            "MIIEpAIBAAKCAQEAvQ8xZ3kLmNoPqRsTuVwXyZ0123456789abcdefghijklmnop\n"
            "-----END RSA PRIVATE KEY-----\n"
            "\n"
            "Then I cracked it.\n"
        )
        output, findings = run_rule("WS002", text)
        self.assertNotIn("DEK-Info", output, "the IV is key material too")
        self.assertNotIn("MIIEpAIBAAKCAQEA", output)
        self.assertIn("-----BEGIN RSA PRIVATE KEY-----", output)
        self.assertIn("-----END RSA PRIVATE KEY-----", output)
        self.assertIn("Then I cracked it.", output)
        self.assertEqual(findings[0].extra["lines_removed"], 4)

    def test_a_second_banner_after_a_truncated_one_is_still_seen(self):
        body = "MIIEpAIBAAKCAQEAvQ8xZ3kLmNoPqRsTuVwXyZ0123456789abcdefghijklmnop"
        text = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "the key is in the vault, not here\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        output, findings = run_rule("WS002", text)
        self.assertNotIn(body, output)
        self.assertIn("the key is in the vault, not here", output)
        self.assertEqual(len(redactions(findings)), 1)
        self.assertEqual(len(warnings(findings)), 1)

    def test_openai_key_prefixes_are_all_redacted(self):
        for value in (
            "sk-abcdefghij0123456789ABCDEFGHIJ",
            "sk-proj-abcdefghij0123456789ABCDEFGHIJ",
            "sk-svcacct-abcdefghij0123456789ABCD",
            "sk-admin-abcdefghij0123456789ABCDEF",
        ):
            with self.subTest(value=value):
                output, _ = run_rule("WS002", value + "\n")
                self.assertNotIn(value, output)

    def test_every_session_cookie_name_is_matched(self):
        for name in (
            "PHPSESSID",
            "JSESSIONID",
            "laravel_session",
            "session",
            "sessionid",
            "_session_id",
            "remember_token",
        ):
            with self.subTest(name=name):
                output, _ = run_rule(
                    "WS002",
                    f"Cookie: {name}=abcdefgh12345678\n",
                    detect_session_cookies=True,
                )
                self.assertNotIn("abcdefgh12345678", output)
                self.assertIn(f"{name}=", output, "the cookie name should survive")
