"""Shared test fixtures backed by isolated SQLite and fake native adapters."""

from collections.abc import Iterator

import pytest
from safety_fakes import FakeBackend, FakeClock, FakeInventory, Rig

from selfheal.remediation.registry import default_registry
from selfheal.safety.contracts import SafetySettings
from selfheal.safety.policy import Policy
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store


@pytest.fixture
def rig() -> Iterator[Rig]:
    """Provide an isolated policy with real SQLite limits and fake platform adapters."""
    store = Store(":memory:")
    clock, inventory, backend = FakeClock(), FakeInventory(), FakeBackend()
    state = SafetyState(store, clock.now)
    settings = SafetySettings(
        enabled_actions=["restart_container", "restart_managed_process", "clear_tmp_files", "rotate_logs"]
    )
    policy = Policy(default_registry(), inventory, backend, state, settings, dry_run=False)
    yield policy, inventory, backend, clock
    store.close()
