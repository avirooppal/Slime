"""One-attempt execution and stability verification using virtual time."""

import threading

import pytest
from safety_fakes import FakeClock, Rig, proposal

from selfheal.config import Config
from selfheal.correlator.engine import Correlator
from selfheal.models import Event, Incident, Kind, State
from selfheal.remediation.executor import Executor
from selfheal.safety.contracts import Snapshot
from selfheal.verifier.stability import StabilityVerifier


def verifier(clock: FakeClock) -> StabilityVerifier:
    """Use the real 120-second default with a virtual monotonic clock."""
    return StabilityVerifier(clock=clock.monotonic, wait=clock.wait)


def test_full_stability_window(rig: Rig) -> None:
    """A single passing check cannot qualify as SUCCESS."""
    policy, inventory, backend, clock = rig
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.status == "success"
    assert result.verification.elapsed_seconds >= 120
    assert result.verification.samples == 25
    assert backend.executions == 1 and backend.rollbacks == 0
    assert (
        policy.state.store.connection.execute("SELECT status FROM actions").fetchone()[0]
        == "success"
    )


def test_toctou_after_reservation(rig: Rig) -> None:
    """A world change between the gate and dispatch aborts without mutation."""
    policy, inventory, backend, clock = rig
    inventory.change_on_call = 2
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.rule == "state_changed_rediagnose" and backend.executions == 0
    assert backend.rollbacks == 0


def test_flap_rolls_back_once_and_escalates(rig: Rig) -> None:
    """Healthy then unhealthy is a flap, not permission to retry the repair."""
    policy, inventory, backend, clock = rig
    backend.health = [True, True, False]
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.status == "escalated" and result.verification.flapping
    assert result.rolled_back and backend.executions == backend.rollbacks == 1
    assert (
        policy.state.store.connection.execute("SELECT status FROM actions").fetchone()[0]
        == "failed"
    )
    assert Executor(policy, verifier(clock)).run(proposal(inventory)).rule == "cooldown"


def test_failed_execute_escalates_without_blind_rollback(rig: Rig) -> None:
    """An operation with uncertain partial completion is not automatically repeated."""
    policy, inventory, backend, clock = rig
    backend.fail_execute = True
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.status == "escalated" and backend.executions == 1 and backend.rollbacks == 0
    assert "do-not-store" not in str(
        policy.state.store.connection.execute("SELECT detail FROM audit_log").fetchall()
    )


def test_kill_during_verification_stops_rollback(rig: Rig) -> None:
    """The kill switch stops the next probe and forbids further rollback mutations."""
    policy, inventory, backend, clock = rig

    def wait(seconds: float) -> None:
        """Simulate an asynchronous operator stop between samples."""
        clock.wait(seconds)
        policy.state.stop.set()

    check = StabilityVerifier(clock=clock.monotonic, wait=wait)
    result = Executor(policy, check).run(proposal(inventory))
    assert result.rule == "kill_switch" and backend.checks == 1 and backend.rollbacks == 0


def test_kill_at_dispatch(rig: Rig) -> None:
    """Stop after final inventory probing still prevents the adapter call."""
    policy, inventory, backend, clock = rig
    original = inventory.snapshot

    def stopping_snapshot(target: str) -> Snapshot:
        """Set the event at the exact second probe."""
        live = original(target)
        if inventory.calls == 2:
            policy.state.stop.set()
        return live

    inventory.snapshot = stopping_snapshot
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.rule == "kill_switch" and backend.executions == 0


def test_lifecycle_integration(rig: Rig) -> None:
    """Authorized mitigation leads to resolution only after stable verification."""
    policy, inventory, _, clock = rig
    store = policy.state.store
    correlator = Correlator(Config(), store)
    with store.connection:
        event = store.event(Event(kind=Kind.ALERT, service="worker", source="test"))
        incident = correlator.ingest(event)
        correlator.transition(incident, State.INVESTIGATING, "read-only evidence collected")
    raw = proposal(inventory).model_copy(update={"incident_id": incident.id})
    result = Executor(policy, verifier(clock), correlator).run(raw, incident=incident)
    assert result.status == "success" and incident.state == State.RESOLVED
    transitions = store.connection.execute(
        "SELECT detail FROM audit_log WHERE rule='state_transition'"
    ).fetchall()
    assert len(transitions) == 4


def test_probe_failure_and_deadline() -> None:
    """Probe exceptions and time spent inside probes cannot produce verified success."""
    clock = FakeClock()

    def slow_probe() -> bool:
        """Cross the total deadline even though the probe returns healthy."""
        clock.wait(301)
        return True

    assert verifier(clock).verify(slow_probe, lambda: False).reason == "verification_timeout"

    def broken_probe() -> bool:
        """Fail without exposing backend messages."""
        raise OSError("offline")

    assert verifier(FakeClock()).verify(broken_probe, lambda: False).reason == "probe_failed"


def test_unavailable_rollback_escalates(rig: Rig) -> None:
    """Irreversible actions do not invent an inverse operation."""
    policy, inventory, backend, clock = rig
    backend.health, backend.reversible = [False], False
    result = Executor(policy, verifier(clock)).run(proposal(inventory))
    assert result.status == "escalated" and not result.rolled_back


def test_hung_probe_has_hard_deadline() -> None:
    """Even an uninterruptible read cannot hold the verifier caller indefinitely."""
    release = threading.Event()

    def probe() -> bool:
        """Wait until released while the caller reaches its small test deadline."""
        release.wait(1)
        return True

    check = StabilityVerifier(probe_timeout_seconds=0.01)
    try:
        assert check.verify(probe, lambda: False).reason == "probe_timeout"
        assert check.verify(probe, lambda: False).reason == "probe_timeout"
    finally:
        release.set()


def test_proposal_cannot_attach_to_wrong_incident(rig: Rig) -> None:
    """Incident ownership is a trusted coordinator constraint, not model-selected JSON."""
    from selfheal.safety.contracts import DiagnosisContext

    policy, inventory, backend, clock = rig
    result = Executor(policy, verifier(clock)).run(
        proposal(inventory), DiagnosisContext(incident_id="another-incident")
    )
    assert result.rule == "incident_mismatch" and backend.executions == 0


def test_reporting_failure_never_undoes_verified_recovery(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed resolution write stops further actions but does not roll back healthy recovery."""
    policy, inventory, backend, clock = rig
    store = policy.state.store
    correlator = Correlator(Config(), store)
    with store.connection:
        event = store.event(Event(kind=Kind.ALERT, service="worker", source="test"))
        incident = correlator.ingest(event)
        correlator.transition(incident, State.INVESTIGATING, "diagnosed")
    original = correlator.transition

    def fail_resolve(current: Incident, state: State, reason: str) -> None:
        """Simulate a persistence/reporting error after successful verification."""
        if state == State.RESOLVED:
            raise OSError("resolution write failed")
        original(current, state, reason)

    monkeypatch.setattr(correlator, "transition", fail_resolve)
    raw = proposal(inventory).model_copy(update={"incident_id": incident.id})
    result = Executor(policy, verifier(clock), correlator).run(raw, incident=incident)
    assert result.rule == "reporting_failure" and result.verification.stable
    assert backend.executions == 1 and backend.rollbacks == 0
    assert incident.state == State.VERIFYING and policy.state.killed()
