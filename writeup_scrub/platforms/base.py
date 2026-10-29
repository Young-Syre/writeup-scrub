"""Platform adapter interface for the retirement check."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

# fetch(url, headers, timeout) -> response body bytes
Fetcher = Callable[[str, dict[str, str], float], bytes]


class RetirementCheckError(Exception):
    """The check could not be completed.

    Raised for a missing token, an unreachable or unparseable API, or an
    unknown platform. It is never raised to mean "this machine is active" --
    that is reported as a :class:`RetirementResult` with ``retired=False``. The
    check fails loudly rather than defaulting to "retired".
    """


@dataclass
class RetirementResult:
    machine: str
    retired: bool
    platform: str
    matched_name: str | None = None
    total_known: int = 0


class PlatformAdapter:
    name: str = ""
    token_env: str = ""
    docs: str = ""

    def __init__(self, token: str | None = None, fetcher: Fetcher | None = None):
        self.token = token
        self.fetcher = fetcher or urlopen_fetch

    def retired_machines(self, timeout: float = 15.0) -> list[str]:
        raise NotImplementedError  # pragma: no cover

    def check(self, machine: str, timeout: float = 15.0) -> RetirementResult:
        names = self.retired_machines(timeout=timeout)
        wanted = machine.strip().lower()
        matched = next((name for name in names if name.strip().lower() == wanted), None)
        return RetirementResult(
            machine=machine,
            retired=matched is not None,
            platform=self.name,
            matched_name=matched,
            total_known=len(names),
        )


def urlopen_fetch(url: str, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RetirementCheckError(
            f"{url} returned HTTP {exc.code} {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RetirementCheckError(f"{url} is unreachable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RetirementCheckError(f"{url} timed out after {timeout}s") from exc
    except OSError as exc:
        # Socket-level failures (connection reset, DNS, TLS) reach us unwrapped.
        raise RetirementCheckError(f"{url} could not be reached: {exc}") from exc
