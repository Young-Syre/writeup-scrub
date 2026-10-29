"""The redaction rule registry.

Rules run in id order. Each is independently toggleable in configuration or on
the command line with ``--enable``/``--disable``.
"""

from __future__ import annotations

from .base import Rule
from .flags import FlagRule
from .identifiers import IdentifierRule
from .network import OperatorNetworkRule
from .notes import PrivateNoteRule
from .paths import LocalPathRule
from .scratch import ScratchContentRule
from .secrets import SecretsRule

ALL_RULES: tuple[Rule, ...] = (
    FlagRule(),
    SecretsRule(),
    LocalPathRule(),
    IdentifierRule(),
    OperatorNetworkRule(),
    PrivateNoteRule(),
    ScratchContentRule(),
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}

__all__ = ["ALL_RULES", "RULES_BY_ID", "Rule"]
