"""Typed action interfaces; diagnostic tools have an entirely separate registry."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from pydantic import Field

from selfheal.models import StrictModel
from selfheal.safety.contracts import Risk, Snapshot


class TargetParams(StrictModel):
    """Symbolic inventory target only; no arbitrary path, PID, URL or shell text."""

    target: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$", strict=True)


class RollbackImageParams(TargetParams):
    """Image rollback requires an exact immutable prior image digest."""

    previous_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$", strict=True)


@dataclass(frozen=True)
class Receipt:
    """Trusted execution receipt; reversible operations retain rollback metadata."""

    detail: str
    changed: bool = True
    rollback_data: dict[str, str] = field(default_factory=dict)


class ActionBackend(Protocol):
    """Bounded platform adapter; names and parameters never become shell code."""

    def available(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Return whether this adapter supports the exact typed operation."""
        ...

    def execute(
        self, name: str, snapshot: Snapshot, params: TargetParams, stopped: Callable[[], bool]
    ) -> Receipt:
        """Apply the operation against the already checked identity."""
        ...

    def verify(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Check action-specific recovery, not merely a successful command exit."""
        ...

    def rollback(
        self, name: str, snapshot: Snapshot, receipt: Receipt, stopped: Callable[[], bool]
    ) -> bool:
        """Undo only when supported and safe; otherwise request escalation."""
        ...


@dataclass(frozen=True)
class Action:
    """Immutable typed action metadata and explicit lifecycle methods."""

    name: str
    schema: type[TargetParams]
    risk: Risk
    target_kinds: frozenset[str]
    blast_radius: int = 1
    cooldown_seconds: int = 300

    def preconditions(
        self, snapshot: Snapshot, params: TargetParams, backend: ActionBackend
    ) -> bool:
        """Reject incompatible targets and refuse restart of a running container."""
        if snapshot.kind not in self.target_kinds:
            return False
        if self.name == "restart_container" and snapshot.state != "crashed":
            return False
        if self.name == "restart_managed_process" and snapshot.state != "crashed":
            return False
        if self.name == "restart_service" and snapshot.healthy:
            return False
        return backend.available(self.name, snapshot, params)

    def execute(
        self,
        snapshot: Snapshot,
        params: TargetParams,
        backend: ActionBackend,
        stopped: Callable[[], bool],
    ) -> Receipt:
        """Invoke the trusted typed adapter, without any model-generated command."""
        return backend.execute(self.name, snapshot, params, stopped)

    def verify(self, snapshot: Snapshot, params: TargetParams, backend: ActionBackend) -> bool:
        """Request action-specific recovery evidence."""
        return backend.verify(self.name, snapshot, params)

    def rollback(
        self,
        snapshot: Snapshot,
        receipt: Receipt,
        backend: ActionBackend,
        stopped: Callable[[], bool],
    ) -> bool:
        """Delegate reversible restoration or explicitly report it unavailable."""
        return backend.rollback(self.name, snapshot, receipt, stopped)
