"""Config loading, strict validation and rule toggling."""

import tempfile
import tomllib
import unittest
from pathlib import Path

from writeup_scrub.config import (
    CONFIG_FILENAME,
    RULE_DEFAULTS,
    TEMPLATE,
    Config,
    ConfigError,
)

from .support import run_pipeline


class DefaultsTests(unittest.TestCase):
    def test_every_rule_is_enabled_by_default(self):
        config = Config()
        for rule_id in RULE_DEFAULTS:
            self.assertTrue(config.is_enabled(rule_id), rule_id)

    def test_ws005_strips_nothing_by_default(self):
        self.assertEqual(Config().for_rule("WS005")["strip_cidrs"], [])

    def test_lab_ranges_are_preserved_by_default(self):
        preserved = Config().for_rule("WS005")["preserve_cidrs"]
        self.assertIn("10.10.0.0/16", preserved)
        self.assertIn("10.129.0.0/16", preserved)

    def test_hygiene_enabled_by_default(self):
        self.assertTrue(Config().hygiene["enabled"])


class TemplateTests(unittest.TestCase):
    def test_template_is_valid_toml(self):
        tomllib.loads(TEMPLATE)

    def test_template_loads_as_a_config(self):
        config = Config.from_dict(tomllib.loads(TEMPLATE))
        self.assertTrue(config.is_enabled("WS001"))
        self.assertEqual(config.for_rule("WS003")["placeholder"], "operator")

    def test_template_mentions_every_rule(self):
        for rule_id in RULE_DEFAULTS:
            self.assertIn(f"[rules.{rule_id}]", TEMPLATE)


class ValidationTests(unittest.TestCase):
    def test_unknown_section_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"nonsense": {}})

    def test_unknown_rule_id_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict({"rules": {"WS999": {"enabled": True}}})
        self.assertIn("unknown rule id", str(caught.exception))

    def test_unknown_rule_key_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict({"rules": {"WS001": {"markr": "x"}}})
        self.assertIn("unknown key", str(caught.exception))

    def test_wrong_type_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"rules": {"WS001": {"enabled": "yes"}}})

    def test_wrong_list_type_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"rules": {"WS005": {"strip_cidrs": [10]}}})

    def test_unknown_hygiene_key_rejected(self):
        with self.assertRaises(ConfigError):
            Config.from_dict({"hygiene": {"nope": True}})

    def test_bad_wikilink_mode_rejected(self):
        with self.assertRaises(ConfigError) as caught:
            Config.from_dict({"rules": {"WS006": {"wikilink_mode": "sideways"}}})
        self.assertIn("wikilink_mode", str(caught.exception))

    def test_valid_override_is_applied(self):
        config = Config.from_dict(
            {"rules": {"WS003": {"placeholder": "redacted", "users": ["dave"]}}}
        )
        self.assertEqual(config.for_rule("WS003")["placeholder"], "redacted")
        self.assertEqual(config.for_rule("WS003")["users"], ["dave"])
        # untouched keys keep their defaults
        self.assertIn("Public", config.for_rule("WS003")["preserve_users"])


class TogglingTests(unittest.TestCase):
    def test_disable_turns_a_rule_off(self):
        config = Config()
        config.apply_toggles([], ["WS001"])
        self.assertFalse(config.is_enabled("WS001"))
        self.assertTrue(config.is_enabled("WS002"))

    def test_toggle_is_case_insensitive(self):
        config = Config()
        config.apply_toggles([], ["ws002"])
        self.assertFalse(config.is_enabled("WS002"))

    def test_enable_overrides_a_disabled_rule(self):
        config = Config.from_dict({"rules": {"WS001": {"enabled": False}}})
        self.assertFalse(config.is_enabled("WS001"))
        config.apply_toggles(["WS001"], [])
        self.assertTrue(config.is_enabled("WS001"))

    def test_unknown_toggle_is_an_error(self):
        with self.assertRaises(ConfigError):
            Config().apply_toggles([], ["WS042"])

    def test_disabled_rule_does_not_fire(self):
        config = Config()
        config.apply_toggles([], ["WS001"])
        config.hygiene["enabled"] = False
        result = run_pipeline(
            "User flag: 0123456789abcdef0123456789abcdef\n", config
        )
        self.assertEqual(result.output, result.original)
        self.assertEqual(result.findings, [])


class DiscoveryTests(unittest.TestCase):
    def test_explicit_missing_config_is_an_error(self):
        with self.assertRaises(ConfigError):
            Config.discover(Path("/nonexistent/.writeup-scrub.toml"))

    def test_discovery_walks_upwards(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / CONFIG_FILENAME).write_text(
                '[rules.WS003]\nplaceholder = "anon"\n', encoding="utf-8"
            )
            nested = root / "writeups" / "htb"
            nested.mkdir(parents=True)
            config = Config.discover(None, start=nested)
            self.assertEqual(config.for_rule("WS003")["placeholder"], "anon")
            self.assertEqual(config.source, root / CONFIG_FILENAME)

    def test_discovery_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Config.discover(None, start=Path(temporary))
            self.assertIsNone(config.source)

    def test_invalid_toml_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / CONFIG_FILENAME
            path.write_text("this is not = = toml", encoding="utf-8")
            with self.assertRaises(ConfigError) as caught:
                Config.load(path)
            self.assertIn("invalid TOML", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
