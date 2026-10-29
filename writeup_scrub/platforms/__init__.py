"""Platform adapters for the opt-in retirement check.

Only the Hack The Box adapter ships. To add another platform, implement
:class:`~writeup_scrub.platforms.base.PlatformAdapter` and register it in
``ADAPTERS``; see the README section "Adding a platform adapter".
"""

from __future__ import annotations

from .base import PlatformAdapter, RetirementCheckError, RetirementResult
from .htb import HackTheBoxAdapter

ADAPTERS: dict[str, type[PlatformAdapter]] = {
    HackTheBoxAdapter.name: HackTheBoxAdapter,
}


def get_adapter(name: str) -> type[PlatformAdapter]:
    try:
        return ADAPTERS[name.lower()]
    except KeyError:
        raise RetirementCheckError(
            f"unknown platform {name!r} (available: {', '.join(sorted(ADAPTERS))})"
        ) from None


__all__ = [
    "ADAPTERS",
    "HackTheBoxAdapter",
    "PlatformAdapter",
    "RetirementCheckError",
    "RetirementResult",
    "get_adapter",
]
