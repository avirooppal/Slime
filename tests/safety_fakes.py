"""Deterministic safety test doubles; never invoke host mutation APIs."""

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta

from selfheal.models import utcnow
from selfheal.remediation.contracts import Receipt, TargetParams
from selfheal.safety.contracts import Proposal, Snapshot
from selfheal.safety.policy import Policy


class FakeClock:
    """Aware wall clock and monotonic clock advanced without real waiting."""

    def __init__(self) -> None:
        """Start with a fixed UTC origin and zero monotonic time."""
        self.wall = utcnow()
        self.seconds = 0.0

    def now(self) -> datetime:
        """Return the injected wall clock."""
        return self.wall + timedelta(seconds=self.seconds)

    def monotonic(self) -> float:
        """Return deterministic elapsed seconds."""
        return self.seconds

    def wait(self, seconds: float) -> None:
        """Advance time, never sleep the test process."""
        self.seconds += seconds


class FakeInventory:
    """Controllable live snapshots without any host mutation."""

    def __init__(self) -> None:
        """Set one eligible crashed container in a known inventory."""
        self.live = Snapshot(
            "container.worker", "container", "id-123", "revision-1", "crashed", False
        )
        self.calls = 0
        self.change_on_call: int | None = None

    def snapshot(self, target: str) -> Snapshot:
        """Reject unknown aliases and simulate a world change when requested."""
        self.calls += 1
        if target != self.live.target:
            raise LookupError("unknown")
        if self.calls == self.change_on_call:
            self.live = replace(self.live, revision="revision-2", state="running")
        return self.live


class FakeBackend:
    """Record adapter calls with programmable failure and stability results."""

    def __init__(self) -> None:
        """Default to available, successful, stable and reversible behavior."""
        self.executions = 0
        self.rollbacks = 0
        self.checks = 0
        self.enabled = True
        self.fail_execute = False
        self.health = [True]
        self.reversible = True

    def available(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Make preconditions explicitly controllable."""
        return self.enabled

    def execute(
        self, name: str, snapshot: Snapshot, params: TargetParams, stopped: Callable[[], bool]
    ) -> Receipt:
        """Never touch real containers or services in unit tests."""
        if stopped():
            raise InterruptedError("operator stopped")
        self.executions += 1
        if self.fail_execute:
            raise RuntimeError("adapter failed with password=do-not-store")
        return Receipt("fake execution")

    def verify(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Return a chosen healthy/unhealthy sequence."""
        value = self.health[min(self.checks, len(self.health) - 1)]
        self.checks += 1
        return value

    def rollback(
        self, name: str, snapshot: Snapshot, receipt: Receipt, stopped: Callable[[], bool]
    ) -> bool:
        """Count one rollback without host side effects."""
        if stopped():
            return False
        self.rollbacks += 1
        return self.reversible


def proposal(inventory: FakeInventory, name: str = "restart_container") -> Proposal:
    """Build a high-confidence typed suggestion against known current state."""
    return Proposal(
        incident_id="incident-1",
        name=name,
        params={"target": inventory.live.target},
        expected_revision=inventory.live.revision,
        confidence=0.95,
    )


Rig = tuple[Policy, FakeInventory, FakeBackend, FakeClock]
