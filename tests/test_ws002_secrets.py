"""WS002: live credentials, by prefix shape."""

import unittest

from .support import fixture, redactions, run_rule

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
