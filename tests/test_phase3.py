"""Phase 3 tests: D1 retrieval, D2 runbooks, ranking planner, coordinator, CLI, and postmortem."""

import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from selfheal.config import Config, Service
from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.diagnosis.retrieval import MemoryRetriever
from selfheal.diagnosis.runbooks import RunbookEngine
from selfheal.interface.cli import app
from selfheal.models import Event, Incident, Kind, utcnow
from selfheal.planner.ranking import Planner
from selfheal.postmortem.generator import PostmortemGenerator
from selfheal.remediation.executor import ExecutionResult
from selfheal.remediation.registry import default_registry
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import Decision, Proposal
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier, Verification
from tests.safety_fakes import FakeBackend, FakeClock, FakeInventory


def make_test_event(
    service: str,
    kind: Kind,
    evidence: str = "",
    template_id: str | None = None,
    attributes: dict[str, object] | None = None,
) -> Event:
    """Helper to construct an aware event."""
    return Event(
        id=str(uuid.uuid4()),
        timestamp=utcnow(),
        kind=kind,
        service=service,
        source="test",
        severity="error",
        evidence=evidence,
        template_id=template_id,
        attributes=attributes or {},
    )


def test_d1_memory_cold_start(tmp_path: Path) -> None:
    """Fresh install with no verified outcomes cleanly abstains."""
    store = Store(tmp_path / "test.db")
    retriever = MemoryRetriever(store)
    incident = Incident(id="inc-1", services=["web"])
    event = make_test_event("web", Kind.ALERT)
    result = retriever.diagnose(incident, [event])

    assert result.status == "abstain"
    assert result.deciding_tier == DiagnosisTier.D1_MEMORY
    assert len(result.candidates) == 0
    assert "cold start" in result.notes[0]
    store.close()


def test_d1_memory_match_verified_outcome(tmp_path: Path) -> None:
    """Matches historical verified successful outcome via BM25."""
    store = Store(tmp_path / "test.db")
    store.save_verified_outcome(
        outcome_id="out-1",
        incident_id="inc-old",
        action_name="restart_container",
        target="container.worker",
        template_ids=["tpl-oom-123"],
        services=["worker"],
        changes=[],
        metrics_pattern=[],
        stable=True,
        payload={"reason": "fixed oom"},
    )

    retriever = MemoryRetriever(store, min_score=0.1)
    incident = Incident(id="inc-new", services=["worker"], root_candidates=["worker"])
    event = make_test_event("worker", Kind.ALERT, template_id="tpl-oom-123")
    result = retriever.diagnose(incident, [event])

    assert result.status == "valid"
    assert result.deciding_tier == DiagnosisTier.D1_MEMORY
    assert len(result.candidates) == 1
    top = result.candidates[0]
    assert top.proposed_action == "restart_container"
    assert top.proposed_params == {"target": "container.worker"}
    assert top.confidence >= 0.7
    assert event.id in top.evidence_event_ids
    store.close()


def test_d2_runbook_container_crash(tmp_path: Path) -> None:
    """Detects container crash on root service and proposes restart_container."""
    config = Config(
        services=[
            Service(name="worker", container_name="worker-cnt"),
        ]
    )
    engine = RunbookEngine(config)
    incident = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    event = make_test_event("worker", Kind.ALERT, evidence="Container exited with exitCode 137 OOMKilled")
    result = engine.diagnose(incident, [event])

    assert result.status == "valid"
    assert result.deciding_tier == DiagnosisTier.D2_RUNBOOK
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.proposed_action == "restart_container"
    assert candidate.proposed_params == {"target": "container.worker"}
    assert candidate.confidence >= 0.90


def test_d2_runbook_root_vs_downstream(tmp_path: Path) -> None:
    """Distinguishes root service failure from downstream symptom."""
    config = Config(
        services=[
            Service(name="database", journal_unit="db.service"),
            Service(name="api", depends_on=["database"], journal_unit="api.service"),
        ]
    )
    engine = RunbookEngine(config)
    # Incident has both database and api failing
    incident = Incident(
        id="inc-1",
        services=["database", "api"],
        root_candidates=["database"],
        downstream=["api"],
    )
    db_event = make_test_event("database", Kind.HEALTH, attributes={"healthy": False})
    api_event = make_test_event("api", Kind.HEALTH, attributes={"healthy": False})

    result = engine.diagnose(incident, [db_event, api_event])
    assert result.status == "valid"
    assert result.deciding_tier == DiagnosisTier.D2_RUNBOOK
    # Should prioritize the root service database
    selected = result.selected
    assert selected is not None
    assert selected.service == "database"
    assert selected.proposed_action == "restart_service"
    assert selected.confidence >= 0.90


def test_d2_runbook_downstream_only_abstains_or_low_confidence() -> None:
    """Downstream failure with potential unmonitored dependency receives low confidence for human review."""
    config = Config(
        services=[
            Service(name="gateway", depends_on=["auth"]),
            Service(name="auth"),
        ]
    )
    engine = RunbookEngine(config)
    incident = Incident(
        id="inc-1",
        services=["gateway"],
        root_candidates=[],
        downstream=["gateway"],
    )
    gw_event = make_test_event("gateway", Kind.HEALTH, attributes={"healthy": False})
    result = engine.diagnose(incident, [gw_event])

    assert result.status == "valid"
    # Downstream-only gets reduced confidence (<0.90) so it does NOT auto-execute
    assert result.selected is not None
    assert result.selected.confidence < 0.90


def test_d2_runbook_disk_pressure_no_quarantine() -> None:
    """Disk >90% diagnoses pressure but refuses quarantine action as capacity fix."""
    config = Config(services=[Service(name="host")])
    engine = RunbookEngine(config)
    incident = Incident(id="inc-1", services=["host"])
    event = make_test_event(
        "host",
        Kind.ALERT,
        attributes={"metric": "disk_percent:/var/log", "value": 95.0, "reason": "disk > 90%"},
    )
    result = engine.diagnose(incident, [event])

    assert result.status == "valid"
    candidate = result.selected
    assert candidate is not None
    assert "Disk space pressure" in candidate.hypothesis
    # Critical requirement: must NOT propose quarantine action
    assert candidate.proposed_action is None


def test_planner_ranking_proven_success_and_blast_radius(tmp_path: Path) -> None:
    """Planner ranks by proven_success * confidence / blast_radius and validates against registry/inventory."""
    registry = default_registry()
    inventory = FakeInventory()  # live target: container.worker, kind: container, blast_radius: 1
    planner = Planner(registry, inventory)

    c1 = CandidateCause(
        hypothesis="H1: restart container",
        service="worker",
        confidence=0.95,
        tier=DiagnosisTier.D2_RUNBOOK,
        proposed_action="restart_container",
        proposed_params={"target": "container.worker"},
        blast_radius=1,
    )
    c2 = CandidateCause(
        hypothesis="H2: unknown action",
        service="worker",
        confidence=0.99,
        tier=DiagnosisTier.D2_RUNBOOK,
        proposed_action="unregistered_hack",
        proposed_params={"target": "container.worker"},
        blast_radius=1,
    )
    c3 = CandidateCause(
        hypothesis="H3: target mismatch",
        service="worker",
        confidence=0.95,
        tier=DiagnosisTier.D2_RUNBOOK,
        proposed_action="restart_container",
        proposed_params={"target": "container.unknown"},
        blast_radius=1,
    )

    diag = DiagnosisResult(
        incident_id="inc-1",
        status="valid",
        deciding_tier=DiagnosisTier.D2_RUNBOOK,
        candidates=[c1, c2, c3],
    )

    ranked = planner.plan(diag, historical_success_weights={"restart_container:container.worker": 1.5})
    # Only c1 is valid registered action matching live inventory
    assert len(ranked) == 1
    assert ranked[0].proposal.name == "restart_container"
    # score = 1.5 * 0.95 / 1 = 1.425
    assert ranked[0].score == pytest.approx(1.425, rel=1e-2)


def test_postmortem_generation() -> None:
    """Generates structured markdown and payload with timeline and verification."""
    incident = Incident(
        id="inc-pm-1",
        services=["worker"],
        root_candidates=["worker"],
        flap_count=0,
    )
    e1 = make_test_event("worker", Kind.ALERT, evidence="OOM crash")
    diag = DiagnosisResult(
        incident_id="inc-pm-1",
        status="valid",
        deciding_tier=DiagnosisTier.D2_RUNBOOK,
        candidates=[
            CandidateCause(
                hypothesis="Container crashed",
                service="worker",
                confidence=0.95,
                proposed_action="restart_container",
                proposed_params={"target": "container.worker"},
            )
        ],
    )
    decision = Decision(
        allowed=True,
        rule="authorized",
        proposal=Proposal(
            incident_id="inc-pm-1",
            name="restart_container",
            params={"target": "container.worker"},
            expected_revision="rev-1",
            confidence=0.95,
        ),
    )
    exec_res = ExecutionResult(
        status="success",
        rule="authorized",
        decision=decision,
        verification=Verification(
            stable=True, reason="healthy_samples", samples=25, elapsed_seconds=120.0
        ),
    )

    md, payload = PostmortemGenerator.generate(incident, [e1], diag, exec_res)
    assert "# Incident Postmortem: inc-pm-1" in md
    assert "OOM crash" in md
    assert "restart_container" in md
    assert "Stable" in md
    assert payload["verified_stable"] is True
    assert payload["diagnosis_tier"] == DiagnosisTier.D2_RUNBOOK


def test_coordinator_dry_run_end_to_end(tmp_path: Path) -> None:
    """Coordinator processes incident in dry-run mode and saves postmortem."""
    db_path = tmp_path / "slime.db"
    config = Config(
        database=str(db_path),
        dry_run=True,
        services=[Service(name="worker", container_name="worker-cnt")],
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

    coord = Coordinator(
        config=config,
        store=store,
        inventory=inv,
        backend=backend,
        state=state,
        verifier=verifier,
    )

    # Ingest crash event
    event = make_test_event("worker", Kind.ALERT, evidence="container died exitCode 137")
    safe_event = store.event(event)
    inc = coord.monitor.correlator.ingest(safe_event)
    assert inc is not None

    diag, proposals, exec_res = coord.handle_incident(inc)
    assert diag.status == "valid"
    assert len(proposals) > 0
    assert exec_res is not None
    # Dry run policy refuses execution
    assert exec_res.status == "refused"
    assert exec_res.rule == "dry_run"
    assert backend.executions == 0

    # Postmortem is saved
    pm = store.postmortem(inc.id)
    assert pm is not None
    assert "Incident Postmortem" in pm["markdown"]
    coord.close()


def test_coordinator_active_execution_and_verified_outcome(tmp_path: Path) -> None:
    """Coordinator executes, verifies stability, and records verified outcome for D1 memory."""
    db_path = tmp_path / "slime.db"
    config = Config(
        database=str(db_path),
        dry_run=False,
        services=[Service(name="worker", container_name="worker-cnt")],
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

    coord = Coordinator(
        config=config,
        store=store,
        inventory=inv,
        backend=backend,
        state=state,
        verifier=verifier,
    )

    event = make_test_event("worker", Kind.ALERT, evidence="container crashed OOMKilled", template_id="tpl-oom-1")
    safe_event = store.event(event)
    inc = coord.monitor.correlator.ingest(safe_event)
    assert inc is not None

    diag, proposals, exec_res = coord.handle_incident(inc)
    assert diag.status == "valid"
    assert len(proposals) > 0
    assert exec_res is not None
    assert exec_res.status == "success"
    assert backend.executions == 1

    # Verified outcome was saved in store
    outcomes = store.verified_outcomes(only_stable=True)
    assert len(outcomes) == 1
    assert outcomes[0]["action_name"] == "restart_container"
    assert outcomes[0]["target"] == "container.worker"
    assert "tpl-oom-1" in outcomes[0]["template_ids"]

    # Now verify D1 memory can match it
    new_inc = Incident(id="inc-2", services=["worker"], root_candidates=["worker"])
    new_event = make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1")
    d1_diag = coord.retriever.diagnose(new_inc, [new_event])
    assert d1_diag.status == "valid"
    assert d1_diag.deciding_tier == DiagnosisTier.D1_MEMORY
    coord.close()


def test_cli_commands_flow(tmp_path: Path) -> None:
    """Test CLI commands: init, status, dry-run, kill-switch, reset-circuit, incidents."""
    runner = CliRunner()
    cfg_file = tmp_path / "config.yaml"

    # 1. init
    res = runner.invoke(app, ["init", "--config", str(cfg_file)])
    assert res.exit_code == 0

    # 2. status
    res = runner.invoke(app, ["status", "--config", str(cfg_file)])
    assert res.exit_code == 0
    assert "Kill switch" in res.output
    assert "Circuit breaker" in res.output

    # 3. kill-switch
    res = runner.invoke(app, ["kill-switch", "true", "--config", str(cfg_file), "--actor", "alice"])
    assert res.exit_code == 0
    assert "ENGAGED" in res.output

    # Disengage kill switch
    res = runner.invoke(app, ["kill-switch", "false", "--config", str(cfg_file), "--actor", "alice"])
    assert res.exit_code == 0
    assert "DISENGAGED" in res.output

    # 4. reset-circuit
    res = runner.invoke(app, ["reset-circuit", "--config", str(cfg_file), "--actor", "alice"])
    assert res.exit_code == 0
    assert "RESET" in res.output

    # 5. dry-run toggle
    res = runner.invoke(app, ["dry-run", "false", "--config", str(cfg_file)])
    assert res.exit_code == 0
    assert "dry_run = False" in res.output

    # 6. approve command
    res = runner.invoke(
        app,
        [
            "approve",
            "inc-100",
            "restart_service",
            "nginx",
            "rev-1",
            "--config",
            str(cfg_file),
            "--actor",
            "bob",
        ],
    )
    assert res.exit_code == 0
    assert "Approval granted" in res.output
    assert "bob" in res.output

    # 7. incidents
    res = runner.invoke(app, ["incidents", "--config", str(cfg_file)])
    assert res.exit_code == 0
