"""Phase 4 tests: isolated process/temp-file chaos harness, scenarios, adversarial injection, and JSONL ground-truth export."""

import json
from pathlib import Path

import pytest

from selfheal.chaos.contracts import FaultType, Scenario
from selfheal.chaos.harness import ChaosHarness
from selfheal.chaos.scenarios import adversarial_scenarios, standard_scenarios
from selfheal.config import Config, Service
from selfheal.runtime import Coordinator
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier
from tests.safety_fakes import FakeBackend, FakeClock, FakeInventory


@pytest.fixture
def chaos_rig(tmp_path: Path):
    """Setup isolated harness with controllable fakes."""
    db_path = tmp_path / "slime.db"
    scratch = tmp_path / "scratch"
    config = Config(
        database=str(db_path),
        dry_run=True,
        services=[
            Service(name="worker", container_name="worker-cnt", process_pid=100),
            Service(name="database", journal_unit="db.service"),
            Service(name="api", depends_on=["database"]),
            Service(name="host"),
        ],
        stability_seconds=10,
    )
    store = Store(db_path)
    inv = FakeInventory()
    backend = FakeBackend()
    clock = FakeClock()
    state = SafetyState(store, now=clock.now)
    verifier = StabilityVerifier(
        window_seconds=10,
        interval_seconds=1,
        timeout_seconds=20,
        clock=clock.monotonic,
        wait=clock.wait,
    )
    coordinator = Coordinator(
        config=config,
        store=store,
        inventory=inv,
        backend=backend,
        state=state,
        verifier=verifier,
    )
    harness = ChaosHarness(scratch, coordinator)
    yield harness, coordinator, tmp_path
    harness.cleanup()
    coordinator.close()


def test_standard_scenarios_labels_and_contracts():
    """Verify scenario catalog has correct, validated attributes."""
    scenarios = standard_scenarios()
    assert len(scenarios) >= 4
    for sc in scenarios:
        assert len(sc.name) > 0
        assert sc.target_service in {"worker", "database", "api", "host"}
        assert sc.fault_type in FaultType


def test_temp_file_fill_bounded_and_cleaned(chaos_rig):
    """Harness only writes to bounded scratch directory and cleans up afterwards."""
    harness, _coordinator, _tmp_path = chaos_rig
    sc = Scenario(
        name="test_fill",
        fault_type=FaultType.TEMP_FILE_FILL,
        target_service="host",
        expected_root_cause="host",
        parameters={"size_kb": 256},
    )
    outcome = harness.run_experiment(sc)
    assert outcome.detected is True
    # Disk > 90% must diagnose pressure but must NOT propose quarantine or execute actions
    assert outcome.executed is False
    assert outcome.planned_action is None
    # Scratch directory files cleaned up
    assert len(list(harness.workspace.glob("*.dat"))) == 0


def test_chaos_rejects_large_fill_and_kills_only_owned_child(chaos_rig):
    """A hostile scenario cannot exhaust disk or nominate a host PID for termination."""
    harness, _coordinator, _tmp_path = chaos_rig
    oversized = Scenario(name="../../outside", fault_type=FaultType.TEMP_FILE_FILL,
                         target_service="host", expected_root_cause="host",
                         parameters={"size_kb": 1025})
    with pytest.raises(ValueError, match="between 1 and 1024"):
        harness.inject(oversized)
    child_fault = Scenario(name="owned_child", fault_type=FaultType.PROCESS_KILL,
                           target_service="worker", expected_root_cause="worker",
                           parameters={"pid": 1})
    event = harness.inject(child_fault)
    assert event.service == "worker"
    assert len(harness.owned_processes) == 1
    assert harness.owned_processes[0].poll() is not None


def test_container_crash_scenario_lifecycle(chaos_rig):
    """End-to-end container crash scenario inject -> detect -> correlate -> diagnose -> policy -> postmortem."""
    harness, _coordinator, _tmp_path = chaos_rig
    sc = Scenario(
        name="test_container_crash",
        fault_type=FaultType.LOG_INJECTION,
        target_service="worker",
        expected_root_cause="worker",
        expected_action="restart_container",
        parameters={"log_line": "fatal: container exited with code 137 OOMKilled"},
    )
    outcome = harness.run_experiment(sc)
    assert outcome.detected is True
    assert outcome.incident_id is not None
    assert outcome.diagnosed_root == "worker"
    assert outcome.planned_action == "restart_container"
    # Coordinator in dry-run mode: policy refuses execution safely
    assert outcome.policy_allowed is False
    assert outcome.policy_rule == "dry_run"
    assert outcome.postmortem_generated is True


def test_adversarial_injection_never_executes_unsafe_actions(chaos_rig):
    """Adversarial prompt/command injection fails to bypass deterministic safety gates."""
    harness, _coordinator, _tmp_path = chaos_rig
    for adv in adversarial_scenarios():
        outcome = harness.run_experiment(adv)
        # Even if logged, no unsafe action is ever dispatched or permitted
        assert outcome.unsafe_action_prevented is True
        assert outcome.policy_allowed is False
        assert outcome.executed is False


def test_ground_truth_jsonl_export(chaos_rig):
    """Ground truth export generates valid JSONL with all required metric fields."""
    harness, _coordinator, tmp_path = chaos_rig
    sc = standard_scenarios()[0]
    outcome = harness.run_experiment(sc)

    export_path = tmp_path / "ground_truth.jsonl"
    harness.export_jsonl([outcome], export_path)

    assert export_path.exists()
    lines = export_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["scenario_name"] == sc.name
    assert data["fault_type"] == sc.fault_type.value
    assert data["detected"] is True
    assert "postmortem_generated" in data
    assert "unsafe_action_prevented" in data
