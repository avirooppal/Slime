"""Tests for Phase 6 Learning: context fingerprints, verified outcomes, sample thresholding, and drift detection."""

from datetime import datetime
from pathlib import Path

from selfheal.config import Config, Service
from selfheal.diagnosis.contracts import DiagnosisTier
from selfheal.learning.contracts import ContextFingerprint, LearningConfig
from selfheal.learning.engine import LearningEngine
from selfheal.learning.fingerprint import extract_fingerprint
from selfheal.models import Event, Incident, Kind, utcnow
from selfheal.runtime import Coordinator
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier
from tests.safety_fakes import FakeBackend, FakeClock, FakeInventory


def make_test_event(
    service: str,
    kind: Kind,
    evidence: str = "error occurred",
    template_id: str | None = None,
    attributes: dict[str, object] | None = None,
    timestamp: datetime | None = None,
) -> Event:
    return Event(
        timestamp=timestamp or utcnow(),
        service=service,
        source="test",
        kind=kind,
        evidence=evidence,
        template_id=template_id,
        attributes=attributes or {},
    )


def test_fingerprint_extraction_and_determinism() -> None:
    """Context fingerprints extract structured features and produce deterministic hashes."""
    inc = Incident(
        id="inc-1",
        services=["worker", "api"],
        root_candidates=["worker"],
        downstream=["api"],
    )
    events = [
        make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1"),
        make_test_event(
            "worker",
            Kind.METRIC,
            attributes={"metric": "cpu.util"},
        ),
        make_test_event(
            "worker",
            Kind.CHANGE,
            attributes={"change": "deploy"},
        ),
    ]

    fp1 = extract_fingerprint(inc, events)
    fp2 = extract_fingerprint(inc, events)

    assert fp1.primary_service == "worker"
    assert fp1.services == ["api", "worker"]
    assert fp1.root_candidates == ["worker"]
    assert fp1.downstream == ["api"]
    assert fp1.template_ids == ["tpl-oom-1"]
    assert "cpu.util:info" in fp1.metric_signatures
    assert "deploy:worker" in fp1.change_signatures
    assert fp1.fingerprint_hash == fp2.fingerprint_hash
    assert len(fp1.fingerprint_hash) == 64


def test_fingerprint_similarity() -> None:
    """Similarity calculation is multi-dimensional and bounded between 0.0 and 1.0."""
    fp_base = ContextFingerprint(
        primary_service="worker",
        services=["api", "worker"],
        root_candidates=["worker"],
        downstream=["api"],
        template_ids=["tpl-oom-1"],
        metric_signatures=["cpu.util:warn"],
        change_signatures=["deploy:worker"],
    )

    # Identical fingerprint has similarity 1.0
    fp_same = ContextFingerprint(
        primary_service="worker",
        services=["api", "worker"],
        root_candidates=["worker"],
        downstream=["api"],
        template_ids=["tpl-oom-1"],
        metric_signatures=["cpu.util:warn"],
        change_signatures=["deploy:worker"],
    )
    assert fp_base.similarity(fp_same) == 1.0

    # Completely disjoint fingerprint has near 0 similarity
    fp_other = ContextFingerprint(
        primary_service="database",
        services=["database", "storage"],
        root_candidates=["database"],
        downstream=["storage"],
        template_ids=["tpl-disk-99"],
        metric_signatures=["disk.full:crit"],
        change_signatures=["migration:database"],
    )
    assert fp_base.similarity(fp_other) < 0.1


def test_context_shift_detection() -> None:
    """Context shift detects root candidate mismatch, conflicting metrics, and template drift."""
    fp_base = ContextFingerprint(
        primary_service="worker",
        services=["api", "worker"],
        root_candidates=["worker"],
        downstream=["api"],
        template_ids=["tpl-oom-1"],
        metric_signatures=["cpu.util:warn"],
    )

    # 1. Root candidate mismatch
    fp_root_shifted = ContextFingerprint(
        primary_service="api",
        services=["api", "worker"],
        root_candidates=["api"],
        downstream=["worker"],
        template_ids=["tpl-oom-1"],
        metric_signatures=["cpu.util:warn"],
    )
    shifted, reasons = fp_base.detect_shift(fp_root_shifted)
    assert shifted is True
    assert any("root candidate mismatch" in r for r in reasons)

    # 2. Conflicting metric signatures (disk pressure instead of cpu)
    fp_metric_drift = ContextFingerprint(
        primary_service="worker",
        services=["api", "worker"],
        root_candidates=["worker"],
        downstream=["api"],
        template_ids=["tpl-oom-1"],
        metric_signatures=["disk.space:crit"],
    )
    shifted, reasons = fp_base.detect_shift(fp_metric_drift)
    assert shifted is True
    assert any("conflicting metric patterns" in r for r in reasons)

    # 3. Severe template divergence
    fp_tpl_drift = ContextFingerprint(
        primary_service="worker",
        services=["api", "worker"],
        root_candidates=["worker"],
        downstream=["api"],
        template_ids=["tpl-network-timeout"],
        metric_signatures=["cpu.util:warn"],
    )
    shifted, reasons = fp_base.detect_shift(fp_tpl_drift)
    assert shifted is True
    assert any("template divergence" in r for r in reasons)


def test_learning_engine_cold_start_and_sample_threshold(tmp_path: Path) -> None:
    """Learning engine cleanly abstains on cold start and enforces minimum sample count."""
    store = Store(tmp_path / "test.db")
    engine = LearningEngine(store, config=LearningConfig(min_samples=2, similarity_threshold=0.85))

    inc = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    events = [make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1")]

    # 1. Cold start: 0 samples
    decision = engine.evaluate_shortcut(inc, events)
    assert decision.eligible is False
    assert decision.shortened is False
    assert "Cold start" in decision.reasons[0]

    # 2. Record 1 stable outcome: sample count 1 < min_samples 2 -> still ineligible
    engine.record_outcome(
        incident=inc,
        events=events,
        action_name="restart_container",
        target="container.worker",
        execution_status="success",
        stable=True,
    )
    decision = engine.evaluate_shortcut(inc, events)
    assert decision.eligible is False
    assert decision.shortened is False
    assert decision.sample_count == 1
    assert "Insufficient verified samples (1 < min 2)" in decision.reasons[0]

    # 3. Record 2nd stable outcome: sample count 2 >= min_samples 2 -> shortcut authorized!
    inc2 = Incident(id="inc-2", services=["worker"], root_candidates=["worker"])
    engine.record_outcome(
        incident=inc2,
        events=events,
        action_name="restart_container",
        target="container.worker",
        execution_status="success",
        stable=True,
    )
    decision = engine.evaluate_shortcut(inc, events)
    assert decision.eligible is True
    assert decision.shortened is True
    assert decision.sample_count == 2
    assert decision.candidate is not None
    assert decision.candidate.proposed_action == "restart_container"
    assert decision.candidate.proposed_params == {"target": "container.worker"}
    assert decision.candidate.tier == DiagnosisTier.D1_MEMORY
    assert decision.candidate.confidence >= 0.90
    store.close()


def test_no_failed_or_unstable_outcome_counts_as_success(tmp_path: Path) -> None:
    """Invariant: Failed or unstable outcomes never count as success and block shortcutting."""
    store = Store(tmp_path / "test.db")
    engine = LearningEngine(store, config=LearningConfig(min_samples=2, similarity_threshold=0.85))

    inc = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    events = [make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1")]

    # Record 1 stable outcome
    engine.record_outcome(
        incident=inc,
        events=events,
        action_name="restart_container",
        target="container.worker",
        execution_status="success",
        stable=True,
    )

    # Record 1 unstable outcome (verification timed out or crashed)
    engine.record_outcome(
        incident=inc,
        events=events,
        action_name="restart_container",
        target="container.worker",
        execution_status="escalated",
        stable=False,
    )

    # Invariant check: only 1 outcome is in verified_outcomes(only_stable=True)
    assert len(store.verified_outcomes(only_stable=True)) == 1
    assert len(store.verified_outcomes(only_stable=False)) == 2

    # Invariant check: unstable outcome blocks shortcutting
    decision = engine.evaluate_shortcut(inc, events)
    assert decision.eligible is False
    assert decision.shortened is False
    assert decision.failed_count == 1
    assert any("Historical failed or unstable outcomes detected" in r for r in decision.reasons)
    store.close()


def test_context_shift_forces_full_diagnosis(tmp_path: Path) -> None:
    """Context shift (different root cause or metric drift) forces full diagnosis despite sample count."""
    store = Store(tmp_path / "test.db")
    engine = LearningEngine(store, config=LearningConfig(min_samples=2, similarity_threshold=0.85))

    inc_base = Incident(
        id="inc-1",
        services=["worker", "api"],
        root_candidates=["worker"],
        downstream=["api"],
    )
    events_base = [
        make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1"),
        make_test_event("worker", Kind.METRIC, attributes={"metric": "cpu.util"}),
    ]

    # Record 2 successful outcomes for base context
    for i in range(2):
        engine.record_outcome(
            incident=Incident(
                id=f"inc-hist-{i}",
                services=["worker", "api"],
                root_candidates=["worker"],
                downstream=["api"],
            ),
            events=events_base,
            action_name="restart_container",
            target="container.worker",
            execution_status="success",
            stable=True,
        )

    # Verify base context gets shortcut
    decision_base = engine.evaluate_shortcut(inc_base, events_base)
    assert decision_base.eligible is True
    assert decision_base.shortened is True

    # New incident with root cause shift: root changed to "api"
    inc_shifted = Incident(
        id="inc-shifted",
        services=["worker", "api"],
        root_candidates=["api"],
        downstream=["worker"],
    )
    decision_shifted = engine.evaluate_shortcut(inc_shifted, events_base)
    assert decision_shifted.eligible is False
    assert decision_shifted.shortened is False
    assert decision_shifted.shift_detected is True
    assert any("Context shift detected" in r for r in decision_shifted.reasons)
    assert any("root candidate mismatch" in r for r in decision_shifted.reasons)
    store.close()


def test_coordinator_learning_lifecycle_and_shortening(tmp_path: Path) -> None:
    """Coordinator enforces full diagnosis under sample threshold, then shortens on repeated incidents."""
    from selfheal.safety.contracts import SafetySettings

    db_path = tmp_path / "slime.db"
    config = Config(
        database=str(db_path),
        dry_run=False,
        services=[Service(name="worker", container_name="worker-cnt")],
        stability_seconds=10,
        learning_min_samples=2,
        learning_similarity_threshold=0.85,
        safety=SafetySettings(enabled_actions=["restart_container"]),
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

    from selfheal.safety.contracts import Snapshot

    # Incident 1: 0 historical samples -> cold start forces full diagnosis (D2 runbook triggers)
    event1 = make_test_event(
        "worker",
        Kind.ALERT,
        evidence="container crashed OOMKilled",
        template_id="tpl-oom-1",
        timestamp=clock.now(),
    )
    safe_event1 = store.event(event1)
    inc1 = coord.monitor.correlator.ingest(safe_event1)
    assert inc1 is not None

    diag1, _, exec1 = coord.handle_incident(inc1)
    assert diag1.status == "valid"
    # Full diagnosis tier used because learning shortcut was not eligible
    assert diag1.deciding_tier == DiagnosisTier.D2_RUNBOOK
    assert exec1 is not None and exec1.status == "success"
    assert len(store.verified_outcomes(only_stable=True)) == 1

    # Advance clock past correlation/cooldown window and simulate a new crashed container
    clock.wait(400)
    inv.live = Snapshot("container.worker", "container", "id-123", "revision-2", "crashed", False)

    # Incident 2: 1 historical sample < min_samples 2 -> forces full diagnosis again
    event2 = make_test_event(
        "worker",
        Kind.ALERT,
        evidence="container crashed OOMKilled",
        template_id="tpl-oom-1",
        timestamp=clock.now(),
    )
    safe_event2 = store.event(event2)
    inc2 = coord.monitor.correlator.ingest(safe_event2)
    assert inc2 is not None

    diag2, _, exec2 = coord.handle_incident(inc2)
    assert diag2.status == "valid"
    assert diag2.deciding_tier == DiagnosisTier.D2_RUNBOOK
    assert exec2 is not None and exec2.status == "success"
    assert len(store.verified_outcomes(only_stable=True)) == 2

    # Advance clock past correlation/cooldown window
    clock.wait(400)
    inv.live = Snapshot("container.worker", "container", "id-123", "revision-3", "crashed", False)

    # Incident 3: 2 historical samples >= min_samples 2 -> learning shortcut authorized!
    event3 = make_test_event(
        "worker",
        Kind.ALERT,
        evidence="container crashed OOMKilled",
        template_id="tpl-oom-1",
        timestamp=clock.now(),
    )
    safe_event3 = store.event(event3)
    inc3 = coord.monitor.correlator.ingest(safe_event3)
    assert inc3 is not None

    diag3 = coord.diagnose_incident(inc3)
    assert diag3.status == "valid"
    assert diag3.deciding_tier == DiagnosisTier.D1_MEMORY
    assert len(diag3.candidates) == 1
    assert diag3.candidates[0].proposed_action == "restart_container"
    assert diag3.candidates[0].proposed_params == {"target": "container.worker"}
    assert any("Learning shortcut" in note for note in diag3.notes)

    coord.close()
