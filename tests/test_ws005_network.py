"""WS005: operator tunnel addresses, with lab ranges preserved."""

import unittest

from .support import fixture, redactions, run_rule


class OperatorNetworkTests(unittest.TestCase):
    def test_nothing_is_stripped_by_default(self):
        source = fixture("ws005_network_positive.md")
        output, findings = run_rule("WS005", source)
        self.assertEqual(output, source)
        self.assertEqual(findings, [])

    def test_configured_cidr_is_stripped(self):
        output, findings = run_rule(
            "WS005", "tun0 is 10.10.14.37\n", strip_cidrs=["10.10.14.0/24"]
        )
        self.assertEqual(output.strip(), "tun0 is [REDACTED: operator address]")
        self.assertEqual(len(redactions(findings)), 1)
        self.assertEqual(findings[0].severity.value, "high")

    def test_lab_target_address_is_preserved(self):
        output, _ = run_rule(
            "WS005",
            "box is 10.10.11.3, tun0 is 10.10.14.37\n",
            strip_cidrs=["10.10.14.0/24"],
        )
        self.assertIn("10.10.11.3", output)
        self.assertNotIn("10.10.14.37", output)

    def test_longest_prefix_wins_over_preserve(self):
        # 10.10.14.0/24 (strip) is more specific than 10.10.0.0/16 (preserve).
        output, _ = run_rule(
            "WS005",
            "10.10.14.37 and 10.10.96.12\n",
            strip_cidrs=["10.10.14.0/24"],
            preserve_cidrs=["10.10.0.0/16"],
        )
        self.assertNotIn("10.10.14.37", output)
        self.assertIn("10.10.96.12", output)

    def test_preserve_wins_when_more_specific(self):
        output, findings = run_rule(
            "WS005",
            "10.10.14.37\n",
            strip_cidrs=["10.0.0.0/8"],
            preserve_cidrs=["10.10.14.0/24"],
        )
        self.assertIn("10.10.14.37", output)
        self.assertEqual(findings, [])

    def test_htb_ranges_preserved_under_a_broad_strip(self):
        output, _ = run_rule(
            "WS005",
            "10.10.11.3 10.129.96.12 10.200.1.5\n",
            strip_cidrs=["10.0.0.0/8"],
        )
        self.assertIn("10.10.11.3", output)
        self.assertIn("10.129.96.12", output)
        self.assertNotIn("10.200.1.5", output)

    def test_address_with_port_is_stripped_cleanly(self):
        output, _ = run_rule(
            "WS005", "callback to 10.10.14.37:4444\n", strip_cidrs=["10.10.14.0/24"]
        )
        self.assertEqual(output.strip(), "callback to [REDACTED: operator address]:4444")

    def test_loopback_preserved_by_default(self):
        output, _ = run_rule(
            "WS005", "127.0.0.1 is local\n", strip_cidrs=["127.0.0.0/8"]
        )
        self.assertIn("127.0.0.1", output)

    def test_invalid_cidr_raises(self):
        with self.assertRaises(ValueError) as caught:
            run_rule("WS005", "10.10.14.37\n", strip_cidrs=["not-a-cidr"])
        self.assertIn("strip_cidrs", str(caught.exception))

    def test_single_host_cidr(self):
        output, _ = run_rule(
            "WS005", "10.10.14.37 10.10.14.38\n", strip_cidrs=["10.10.14.37/32"]
        )
        self.assertNotIn("10.10.14.37", output)
        self.assertIn("10.10.14.38", output)


if __name__ == "__main__":
    unittest.main()
