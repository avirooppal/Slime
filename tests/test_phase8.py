"""Tests for Phase 8: D4 Opt-In Cloud LLM, D5 Opt-In Laya Classifier, Redaction, Caps, and Degradation."""

from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from selfheal.config import Config, Service
from selfheal.diagnosis.cloud_client import CloudInvestigator
from selfheal.diagnosis.cloud_contracts import CloudBudget
from selfheal.diagnosis.contracts import DiagnosisTier
from selfheal.diagnosis.laya_classifier import LayaClassifier
from selfheal.models import Event, Incident, Kind, utcnow
from selfheal.runtime import Coordinator
from selfheal.storage.store import Store
from tests.safety_fakes import FakeBackend, FakeInventory


def make_test_event(
    service: str,
    kind: Kind,
    evidence: str = "test error",
    template_id: str | None = None,
    attributes: dict[str, object] | None = None,
    source: str = "test",
) -> Event:
    return Event(
        timestamp=utcnow(),
        service=service,
        source=source,
        kind=kind,
        evidence=evidence,
        template_id=template_id,
        attributes=attributes or {},
    )


def test_secrets_never_enter_config_invariant() -> None:
    """Config validator strictly forbids API keys, secrets, tokens, and raw credentials."""
    # 1. Secret keys in dictionary mapping
    with pytest.raises(ValueError, match="Secrets forbidden in config"):
        Config.model_validate({"api_key": "sk-12345"})

    with pytest.raises(ValueError, match="Secrets forbidden in config"):
        Config.model_validate({"cloud_secret": "my-secret"})

    with pytest.raises(ValueError, match="Secrets forbidden in config"):
        Config.model_validate({"auth_token": "bearer-token"})

    # 2. Secret values in string fields
    with pytest.raises(ValueError, match="Secrets forbidden in config values"):
        Config.model_validate({"ollama_model": "sk-ant-api-key-test"})


def test_d4_summary_only_redaction(tmp_path: Path) -> None:
    """D4 summary request strictly sanitizes passwords, credentials, and bounds evidence."""
    store = Store(tmp_path / "test.db")
    config = Config(cloud_enabled=True)
    investigator = CloudInvestigator(config, store)

    inc = Incident(
        id="inc-1",
        services=["worker", "api"],
        root_candidates=["worker"],
        downstream=["api"],
    )
    events = [
        make_test_event(
            "worker",
            Kind.ALERT,
            evidence="fatal: auth failed for password=super_secret_password and token=12345",
            template_id="tpl-auth-1",
        ),
        make_test_event(
            "worker",
            Kind.METRIC,
            attributes={"metric": "cpu.util"},
        ),
    ]

    summary = investigator.build_summary_request(inc, events)
    assert "super_secret_password" not in summary.redacted_evidence_summary
    assert "12345" not in summary.redacted_evidence_summary
    assert "REDACTED" in summary.redacted_evidence_summary
    assert summary.root_candidates == ["worker"]
    assert "tpl-auth-1" in summary.template_ids
    store.close()


def test_d4_spend_and_call_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hourly call caps and spend caps are enforced before cloud invocation."""
    store = Store(tmp_path / "test.db")
    config = Config(
        cloud_enabled=True,
        cloud_max_calls_per_hour=2,
        cloud_max_spend_usd=0.5,
    )
    monkeypatch.setenv("SLIME_CLOUD_API_KEY", "env-key-test")
    investigator = CloudInvestigator(config, store)

    inc = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    events = [make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1")]

    # Budget model checks
    budget = CloudBudget(max_calls_per_hour=2, max_spend_usd=0.5)
    hour = "2026-10-04-12"
    can_call, _ = budget.can_call(hour)
    assert can_call is True

    budget.record_call(estimated_cost=0.02)
    can_call, _ = budget.can_call(hour)
    assert can_call is True

    budget.record_call(estimated_cost=0.02)
    can_call, reason = budget.can_call(hour)
    assert can_call is False
    assert "Cloud call cap reached" in reason

    # Spend cap check
    budget_spend = CloudBudget(max_calls_per_hour=10, max_spend_usd=0.2)
    budget_spend.record_call(estimated_cost=0.25)
    can_call_spend, reason_spend = budget_spend.can_call(hour)
    assert can_call_spend is False
    assert "Cloud spend cap reached" in reason_spend

    # Ensure investigator honors budget when calling diagnose
    investigator.budget.record_call(estimated_cost=1.0)
    diag_capped = investigator.diagnose(inc, events)
    assert diag_capped.status == "abstain"
    assert "Cloud spend cap reached" in diag_capped.notes[0]

    store.close()


def test_d4_graceful_degradation_absent_key_and_network_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D4 cleanly degrades to local baseline if key is absent or network fails."""
    store = Store(tmp_path / "test.db")
    config = Config(cloud_enabled=True)

    # 1. Key absent from environment
    monkeypatch.delenv("SLIME_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    investigator = CloudInvestigator(config, store)
    inc = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    events = [make_test_event("worker", Kind.ALERT, template_id="tpl-oom-1")]

    result = investigator.diagnose(inc, events)
    assert result.status == "abstain"
    assert result.deciding_tier == DiagnosisTier.D4_CLOUD_LLM
    assert "env-only" in result.notes[0]

    # Verify audit log recorded key_missing
    audits = [r[4] for r in store.connection.execute("SELECT * FROM audit_log WHERE subject='cloud_investigator'").fetchall()]
    assert any("no cloud api key" in a for a in audits)

    # 2. Key present but network error / timeout
    monkeypatch.setenv("SLIME_CLOUD_API_KEY", "env-key-test")
    mock_client = Mock(spec=httpx.Client)
    mock_client.post.side_effect = httpx.ConnectTimeout("connection timed out")

    investigator_with_mock = CloudInvestigator(config, store, http_client=mock_client)
    res_timeout = investigator_with_mock.diagnose(inc, events)
    assert res_timeout.status == "abstain"
    assert "degrading once to local baseline" in res_timeout.notes[0]
    store.close()


def test_d5_laya_classifier_calibration_and_gates(tmp_path: Path) -> None:
    """Laya classifier accurately classifies closed-set incidents with calibrated confidence."""
    store = Store(tmp_path / "test.db")
    config = Config(laya_enabled=True, laya_confidence_threshold=0.80)
    laya = LayaClassifier(config, store)

    # 1. Container crash test
    inc_crash = Incident(id="inc-crash", services=["worker"], root_candidates=["worker"])
    events_crash = [
        make_test_event(
            "worker",
            Kind.ALERT,
            evidence="fatal: container exited with code 137 OOMKilled",
            template_id="tpl-oom-137",
        )
    ]
    diag = laya.diagnose(inc_crash, events_crash)
    assert diag.status == "valid"
    assert diag.deciding_tier == DiagnosisTier.D5_LAYA
    assert len(diag.candidates) == 1
    top = diag.candidates[0]
    assert top.proposed_action == "restart_container"
    assert top.confidence >= 0.80
    assert top.proposed_params == {"target": "container.worker"}

    # 2. Disk pressure test: quarantine does NOT reclaim disk -> Laya abstains
    inc_disk = Incident(id="inc-disk", services=["host"], root_candidates=["host"])
    events_disk = [
        make_test_event(
            "host",
            Kind.METRIC,
            attributes={"metric": "disk_percent"},
        )
    ]
    diag_disk = laya.diagnose(inc_disk, events_disk)
    assert diag_disk.status == "abstain"
    assert "requires human review" in diag_disk.notes[0]

    # 3. Laya disabled: degrades once
    config_disabled = Config(laya_enabled=False)
    laya_disabled = LayaClassifier(config_disabled, store)
    diag_dis = laya_disabled.diagnose(inc_crash, events_crash)
    assert diag_dis.status == "abstain"
    assert "disabled in configuration" in diag_dis.notes[0]
    store.close()


def test_d5_laya_ablation_analysis(tmp_path: Path) -> None:
    """Laya feature ablation measures drop in accuracy when signal groups are removed."""
    store = Store(tmp_path / "test.db")
    config = Config(laya_enabled=True)
    laya = LayaClassifier(config, store)

    samples = [
        (
            Incident(id="s1", services=["worker"], root_candidates=["worker"]),
            [make_test_event("worker", Kind.ALERT, evidence="exitCode 137 OOMKilled", template_id="oom-1")],
            "container_crash",
        ),
        (
            Incident(id="s2", services=["api"], root_candidates=["api"]),
            [make_test_event("api", Kind.HEALTH, evidence="connection refused")],
            "service_health_hang",
        ),
        (
            Incident(id="s3", services=["db"], root_candidates=["db"]),
            [make_test_event("db", Kind.METRIC, attributes={"metric": "disk_used"})],
            "disk_pressure",
        ),
        (
            Incident(id="s4", services=["auth"], root_candidates=["auth"]),
            [make_test_event("auth", Kind.ALERT, source="process", evidence="process exited unexpectedly")],
            "process_crash",
        ),
    ]

    reports = laya.run_ablation(samples)
    assert len(reports) == 5
    assert all(r.baseline_accuracy > 0.0 for r in reports)
    # The most sensitive feature group has rank 1
    assert reports[0].importance_rank == 1
    store.close()


def test_end_to_end_coordinator_hierarchy_with_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Coordinator prioritizes D5 Laya and D4 Cloud when active, and gracefully falls back to D2 on failure."""
    db_path = tmp_path / "slime.db"
    store = Store(db_path)
    inv = FakeInventory()
    backend = FakeBackend()

    # 1. Run with Laya enabled
    config_laya = Config(
        database=str(db_path),
        dry_run=False,
        laya_enabled=True,
        cloud_enabled=False,
        services=[Service(name="worker", container_name="worker-cnt")],
    )
    coord_laya = Coordinator(
        config=config_laya,
        store=store,
        inventory=inv,
        backend=backend,
        verifier=Mock(verify=Mock()),
    )
    ev = make_test_event("worker", Kind.ALERT, evidence="container died 137 OOMKilled", template_id="oom-1")
    stored_ev = store.event(ev)
    inc = Incident(id="inc-oom", services=["worker"], root_candidates=["worker"], event_ids=[stored_ev.id])
    store.save_incident(inc)

    diag_laya = coord_laya.diagnose_incident(inc)
    assert diag_laya.status == "valid"
    assert diag_laya.deciding_tier == DiagnosisTier.D5_LAYA
    assert diag_laya.candidates[0].proposed_action == "restart_container"
    coord_laya.close()

    # 2. Run with Laya failing confidence gate and Cloud failing key: degrades cleanly to D2 Runbook
    store2 = Store(db_path)
    config_fallback = Config(
        database=str(db_path),
        dry_run=False,
        laya_enabled=True,
        laya_confidence_threshold=0.99,  # Force confidence gate failure
        cloud_enabled=True,              # Cloud enabled but no key in env
        services=[Service(name="worker", container_name="worker-cnt")],
    )
    monkeypatch.delenv("SLIME_CLOUD_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    coord_fallback = Coordinator(
        config=config_fallback,
        store=store2,
        inventory=inv,
        backend=backend,
        verifier=Mock(verify=Mock()),
    )
    ev2 = make_test_event("worker", Kind.ALERT, evidence="Container exited with exitCode 137 OOMKilled")
    stored_ev2 = store2.event(ev2)
    inc2 = Incident(id="inc-oom-2", services=["worker"], root_candidates=["worker"], event_ids=[stored_ev2.id])
    store2.save_incident(inc2)

    diag_fallback = coord_fallback.diagnose_incident(inc2)
    assert diag_fallback.status == "valid"
    # Preserves local D2 runbook baseline!
    assert diag_fallback.deciding_tier == DiagnosisTier.D2_RUNBOOK
    assert diag_fallback.candidates[0].proposed_action == "restart_container"
    coord_fallback.close()
