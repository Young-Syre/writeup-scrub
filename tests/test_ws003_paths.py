"""WS003: the operator's home directory, not the target's."""

import unittest

from .support import fixture, redactions, run_rule


class LocalPathTests(unittest.TestCase):
    def test_linux_home_rewritten_trailing_path_kept(self):
        output, findings = run_rule("WS003", "cd /home/jordan/htb/blackfield/loot\n")
        self.assertEqual(output.strip(), "cd /home/operator/htb/blackfield/loot")
        self.assertEqual(len(redactions(findings)), 1)
        self.assertEqual(findings[0].severity.value, "medium")

    def test_macos_home_rewritten(self):
        output, _ = run_rule("WS003", "/Users/jordan/Library/Preferences\n")
        self.assertEqual(output.strip(), "/Users/operator/Library/Preferences")

    def test_windows_home_rewritten(self):
        output, _ = run_rule("WS003", r"C:\Users\jordan\Desktop\tool.exe" + "\n")
        self.assertEqual(output.strip(), r"C:\Users\operator\Desktop\tool.exe")

    def test_windows_forward_slash_home_rewritten(self):
        output, _ = run_rule("WS003", "C:/Users/jordan/Desktop/tool.exe\n")
        self.assertEqual(output.strip(), "C:/Users/operator/Desktop/tool.exe")

    def test_bare_home_without_trailing_path(self):
        output, _ = run_rule("WS003", "my home is /home/jordan\n")
        self.assertEqual(output.strip(), "my home is /home/operator")

    def test_custom_placeholder(self):
        output, _ = run_rule("WS003", "/home/jordan/x\n", placeholder="user")
        self.assertEqual(output.strip(), "/home/user/x")

    def test_users_allowlist_limits_rewriting(self):
        output, findings = run_rule(
            "WS003", "/home/jordan/x and /home/svc_apache/y\n", users=["jordan"]
        )
        self.assertIn("/home/operator/x", output)
        self.assertIn("/home/svc_apache/y", output, "target home was rewritten")
        self.assertEqual(len(redactions(findings)), 1)

    def test_preserve_users_protects_windows_defaults(self):
        text = (
            r"C:\Users\Administrator\Desktop\root.txt"
            "\n"
            r"C:\Users\Public\Documents\x.csv"
            "\n"
        )
        output, findings = run_rule("WS003", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_placeholder_is_not_rewritten_again(self):
        output, findings = run_rule("WS003", "/home/operator/x\n")
        self.assertEqual(output.strip(), "/home/operator/x")
        self.assertEqual(findings, [])

    def test_system_paths_untouched(self):
        text = "/root/.ssh/id_rsa /etc/shadow /var/www/html /usr/share/wordlists\n"
        output, findings = run_rule("WS003", text)
        self.assertEqual(output, text)
        self.assertEqual(findings, [])

    def test_positive_fixture(self):
        output, findings = run_rule("WS003", fixture("ws003_paths_positive.md"))
        self.assertNotIn("/home/jordan", output)
        self.assertNotIn(r"C:\Users\jordan", output)
        self.assertNotIn("/Users/jordan", output)
        self.assertEqual(len(redactions(findings)), 4)

    def test_negative_fixture_untouched(self):
        source = fixture("ws003_paths_negative.md")
        output, findings = run_rule("WS003", source, users=["jordan"])
        self.assertEqual(output, source)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
