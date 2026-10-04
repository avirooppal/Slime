"""Small inventory contract independent of collectors and action implementations."""

import hashlib
import json
from collections.abc import Mapping
from typing import Protocol

from selfheal.safety.contracts import Snapshot


class Inventory(Protocol):
    """Only explicit or discovered inventory targets can be probed by actions."""

    def snapshot(self, target: str) -> Snapshot:
        """Re-read live target state; raise LookupError for unknown targets."""
        ...


def revision(values: Mapping[str, object]) -> str:
    """Hash identity and action-relevant state without retaining raw evidence."""
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
