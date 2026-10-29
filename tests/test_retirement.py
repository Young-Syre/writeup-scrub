"""The retirement check, with the network mocked. No test touches the network."""

import json
import unittest

from writeup_scrub.platforms import (
    ADAPTERS,
    HackTheBoxAdapter,
    RetirementCheckError,
    get_adapter,
)


def fake_fetcher(payload, *, calls=None):
    def fetch(url, headers, timeout):
        if calls is not None:
            calls.append((url, headers, timeout))
        return json.dumps(payload).encode("utf-8")

    return fetch


class AdapterRegistryTests(unittest.TestCase):
    def test_only_htb_ships(self):
        self.assertEqual(sorted(ADAPTERS), ["htb"])

    def test_lookup_is_case_insensitive(self):
        self.assertIs(get_adapter("HTB"), HackTheBoxAdapter)

    def test_unknown_platform_raises(self):
        with self.assertRaises(RetirementCheckError) as caught:
            get_adapter("thm")
        self.assertIn("unknown platform", str(caught.exception))


class TokenTests(unittest.TestCase):
    def test_missing_token_fails_loudly(self):
        adapter = HackTheBoxAdapter(token=None, fetcher=fake_fetcher({}))
        with self.assertRaises(RetirementCheckError) as caught:
            adapter.check("Blackfield")
        message = str(caught.exception)
        self.assertIn("HTB_TOKEN", message)
        self.assertIn("bundles no token", message)

    def test_token_is_sent_as_a_bearer_header(self):
        calls = []
        adapter = HackTheBoxAdapter(
            token="my-own-token",
            fetcher=fake_fetcher({"info": [{"name": "Blackfield"}]}, calls=calls),
        )
        adapter.check("Blackfield")
        self.assertEqual(calls[0][1]["Authorization"], "Bearer my-own-token")


class ReachableTests(unittest.TestCase):
    def test_retired_machine_is_confirmed(self):
        adapter = HackTheBoxAdapter(
            token="t",
            fetcher=fake_fetcher(
                {"info": [{"name": "Blackfield"}, {"name": "Forest"}]}
            ),
        )
        result = adapter.check("Blackfield")
        self.assertTrue(result.retired)
        self.assertEqual(result.matched_name, "Blackfield")
        self.assertEqual(result.total_known, 2)
        self.assertEqual(result.platform, "htb")

    def test_name_matching_is_case_insensitive(self):
        adapter = HackTheBoxAdapter(
            token="t", fetcher=fake_fetcher({"info": [{"name": "Blackfield"}]})
        )
        self.assertTrue(adapter.check("blackfield").retired)
        self.assertTrue(adapter.check("  BLACKFIELD ").retired)

    def test_active_machine_is_reported_not_raised(self):
        adapter = HackTheBoxAdapter(
            token="t", fetcher=fake_fetcher({"info": [{"name": "Forest"}]})
        )
        result = adapter.check("BrandNewBox")
        self.assertFalse(result.retired)
        self.assertIsNone(result.matched_name)

    def test_data_response_shape_is_supported(self):
        adapter = HackTheBoxAdapter(
            token="t",
            fetcher=fake_fetcher(
                {"data": [{"name": "Lame"}], "meta": {"last_page": 1}}
            ),
        )
        self.assertTrue(adapter.check("Lame").retired)

    def test_pagination_is_followed(self):
        pages = {
            1: {"data": [{"name": "A"}], "meta": {"last_page": 2}},
            2: {"data": [{"name": "Blackfield"}], "meta": {"last_page": 2}},
        }

        def fetch(url, headers, timeout):
            page = 2 if "page=2" in url else 1
            return json.dumps(pages[page]).encode("utf-8")

        adapter = HackTheBoxAdapter(token="t", fetcher=fetch)
        result = adapter.check("Blackfield")
        self.assertTrue(result.retired)
        self.assertEqual(result.total_known, 2)


class UnreachableTests(unittest.TestCase):
    def test_network_failure_raises_rather_than_assuming_retired(self):
        def fetch(url, headers, timeout):
            raise RetirementCheckError("labs.hackthebox.com is unreachable: timed out")

        adapter = HackTheBoxAdapter(token="t", fetcher=fetch)
        with self.assertRaises(RetirementCheckError) as caught:
            adapter.check("Blackfield")
        self.assertIn("unreachable", str(caught.exception))

    def test_non_json_response_raises(self):
        adapter = HackTheBoxAdapter(
            token="t", fetcher=lambda url, headers, timeout: b"<html>login</html>"
        )
        with self.assertRaises(RetirementCheckError) as caught:
            adapter.check("Blackfield")
        self.assertIn("non-JSON", str(caught.exception))

    def test_unexpected_shape_raises(self):
        adapter = HackTheBoxAdapter(
            token="t", fetcher=fake_fetcher({"machines": [{"name": "X"}]})
        )
        with self.assertRaises(RetirementCheckError) as caught:
            adapter.check("Blackfield")
        self.assertIn("API shape changed", str(caught.exception))

    def test_empty_list_raises_rather_than_guessing(self):
        adapter = HackTheBoxAdapter(token="t", fetcher=fake_fetcher({"info": []}))
        with self.assertRaises(RetirementCheckError) as caught:
            adapter.check("Blackfield")
        self.assertIn("refusing to guess", str(caught.exception))

    def test_json_array_response_raises(self):
        adapter = HackTheBoxAdapter(
            token="t", fetcher=lambda url, headers, timeout: b"[1, 2, 3]"
        )
        with self.assertRaises(RetirementCheckError):
            adapter.check("Blackfield")


if __name__ == "__main__":
    unittest.main()
