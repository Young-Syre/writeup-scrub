"""Hack The Box retirement adapter.

Publishing a writeup for an active machine breaks the Hack The Box rules, so
this check exists to make that mistake impossible to make by accident.

The API needs *your* token. None is bundled, and the tool never reads one from
anywhere but the ``HTB_TOKEN`` environment variable (override with
``--token-env``). Create an App Token in your HTB profile settings.
"""

from __future__ import annotations

import json

from .base import PlatformAdapter, RetirementCheckError

API_BASE = "https://labs.hackthebox.com/api/v4"
RETIRED_URL = API_BASE + "/machine/list/retired/paginated"
MAX_PAGES = 50
PER_PAGE = 100


class HackTheBoxAdapter(PlatformAdapter):
    name = "htb"
    token_env = "HTB_TOKEN"
    docs = "https://app.hackthebox.com/profile/settings (App Tokens)"

    def retired_machines(self, timeout: float = 15.0) -> list[str]:
        if not self.token:
            raise RetirementCheckError(
                "no API token supplied: set "
                f"{self.token_env} to your own Hack The Box App Token "
                f"({self.docs}). writeup-scrub bundles no token."
            )
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "writeup-scrub (+https://github.com/Young-Syre/writeup-scrub)",
        }
        names: list[str] = []
        page = 1
        while page <= MAX_PAGES:
            url = f"{RETIRED_URL}/?per_page={PER_PAGE}&page={page}"
            raw = self.fetcher(url, headers, timeout)
            payload = _decode(raw, url)
            batch, last_page = _extract(payload, url)
            if not batch:
                break
            names.extend(batch)
            if last_page is None or page >= last_page:
                break
            page += 1
        if not names:
            raise RetirementCheckError(
                f"{RETIRED_URL} returned no machines; refusing to guess whether "
                "a machine is retired"
            )
        return names


def _decode(raw: bytes, url: str) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RetirementCheckError(f"{url} returned a non-JSON response: {exc}") from exc


def _extract(payload: object, url: str) -> tuple[list[str], int | None]:
    """Pull machine names out of either known response shape."""
    if not isinstance(payload, dict):
        raise RetirementCheckError(f"{url} returned {type(payload).__name__}, expected an object")
    machines = payload.get("info")
    if machines is None:
        machines = payload.get("data")
    if not isinstance(machines, list):
        raise RetirementCheckError(
            f"{url} response has no 'info' or 'data' list -- the API shape changed"
        )
    names: list[str] = []
    for item in machines:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    last_page = None
    meta = payload.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("last_page"), int):
        last_page = meta["last_page"]
    return names, last_page
