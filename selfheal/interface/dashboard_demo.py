"""Seed a rich, deterministic demo database from the ChaosHarness for --demo mode."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from selfheal.chaos.harness import ChaosHarness
from selfheal.chaos.scenarios import adversarial_scenarios, standard_scenarios
from selfheal.config import Config, Maintenance, ManagedFileSettings, Service
from selfheal.models import Event, Incident, Kind, State, utcnow
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import Proposal, SafetySettings
from selfheal.safety.state import SafetyState, proposal_digest
from selfheal.storage.store import Store


def build_demo_config(db_path: Path, workspace_dir: Path, *, preset: str = "default") -> Config:
    """Construct a complete demo configuration with dependency map, critical flags, and maintenance window."""
    now = utcnow()
    worker_log = workspace_dir / "worker.log"
    nginx_conf = workspace_dir / "nginx.conf"
    tmp_fill = workspace_dir / "scratch_cache.tmp"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    if not worker_log.exists():
        worker_log.write_text("2026-10-17T05:00:00Z INFO worker boot ready\n", encoding="utf-8")
    if not nginx_conf.exists():
        nginx_conf.write_text("upstream web_backend { server 127.0.0.1:8000; }\n", encoding="utf-8")
    if not tmp_fill.exists():
        tmp_fill.write_text("temporary cache payload\n", encoding="utf-8")

    dry_run = preset not in ("live", "killed", "circuit_open")
    learning_period = preset == "learning"
    enabled_actions = (
        ["restart_container", "rotate_logs"]
        if preset in ("live", "killed", "circuit_open", "default")
        else []
    )

    return Config(
        database=str(db_path),
        dry_run=dry_run,
        learning_period=learning_period,
        metrics_enabled=True,
        stability_seconds=120,
        safety=SafetySettings(
            minimum_confidence=0.9,
            cooldown_seconds=300,
            max_auto_per_hour=5,
            failure_limit=3,
            enabled_actions=enabled_actions,
        ),
        services=[
            Service(
                name="nginx",
                critical=False,
                depends_on=["web"],
                configs=[str(nginx_conf)],
                http_url="http://127.0.0.1:8080/health",
            ),
            Service(
                name="web",
                critical=False,
                depends_on=["worker", "database"],
                container_name="slime-demo-web-1",
                http_url="http://127.0.0.1:8000/health",
            ),
            Service(
                name="worker",
                critical=False,
                depends_on=["database"],
                logs=[str(worker_log)],
                container_name="slime-demo-worker-1",
            ),
            Service(
                name="database",
                critical=True,
                depends_on=[],
                journal_unit="postgresql.service",
                tcp_host="127.0.0.1",
                tcp_port=5432,
            ),
            Service(
                name="batch-archiver",
                critical=False,
                depends_on=["database"],
                container_name="slime-demo-archiver-1",
            ),
        ],
        maintenance=[
            Maintenance(
                services=["batch-archiver"],
                start=now - timedelta(minutes=30),
                end=now + timedelta(hours=2),
            ),
            Maintenance(
                services=["database"],
                start=datetime(2026, 10, 18, 2, 0, tzinfo=timezone.utc),
                end=datetime(2026, 10, 18, 4, 0, tzinfo=timezone.utc),
            ),
        ],
        managed_files=[
            ManagedFileSettings(
                target="file.worker_log",
                path=str(worker_log),
                kind="log_file",
                minimum_age_seconds=60,
                quiescent=True,
                contains_secrets=False,
                critical=False,
            ),
        ],
    )


def seed_demo_database(
    base_dir: Path,
    *,
    preset: str = "default",
) -> tuple[Config, Store]:
    """Seed a comprehensive SQLite store using ChaosHarness covering all required states."""
    base_dir.mkdir(parents=True, exist_ok=True)
    db_path = base_dir / f"demo_{preset}.db"
    if db_path.exists():
        db_path.unlink()

    ws_dir = base_dir / "workspace"
    config = build_demo_config(db_path, ws_dir, preset=preset)
    store = Store(db_path)
    state = SafetyState(store)
    now = utcnow()

    if preset == "empty":
        # Empty state: no incidents, no actions, fresh store
        store.audit("system", "demo_initialized", "empty demo workspace ready")
        return config, store

    # Use ChaosHarness to generate real fault events from standard & adversarial scenarios
    scratch_coord = Coordinator(config, store=Store(":memory:"))
    harness = ChaosHarness(ws_dir / "chaos_scratch", scratch_coord)
    scenarios = standard_scenarios()
    adv_scenarios = adversarial_scenarios()
    try:
        ev_oom = harness.inject(scenarios[0])  # container_oom_crash on worker
        ev_db = harness.inject(scenarios[1])  # root_service_health_failure on database
        ev_adv = harness.inject(adv_scenarios[0])  # prompt_injection_rm_rf
    finally:
        harness.cleanup()
        scratch_coord.close()

    # 1. Resolved incident with postmortem (inc-resolved-01)
    ev_res_1 = Event(
        id="ev-res-01",
        timestamp=now - timedelta(minutes=42),
        kind=ev_oom.kind,
        service="worker",
        source="container_logs",
        severity="error",
        evidence=ev_oom.evidence,
        template_id="tpl-oom-137",
        attributes=ev_oom.attributes,
    )
    ev_res_2 = Event(
        id="ev-res-02",
        timestamp=now - timedelta(minutes=41, seconds=30),
        kind=Kind.HEALTH,
        service="web",
        source="http_probe",
        severity="warning",
        evidence="upstream worker timed out during batch job",
        attributes={"healthy": False, "upstream": "worker"},
    )
    store.event(ev_res_1)
    store.event(ev_res_2)
    inc_resolved = Incident(
        id="inc-resolved-01",
        opened_at=now - timedelta(minutes=42),
        state=State.RESOLVED,
        services=["worker", "web"],
        root_candidates=["worker"],
        downstream=["web"],
        event_ids=[ev_res_1.id, ev_res_2.id],
        flap_count=0,
    )
    store.save_incident(inc_resolved)
    store.save_hypothesis(
        hypothesis_id="hyp-res-01",
        incident_id=inc_resolved.id,
        tier="D2_RUNBOOK",
        root_cause="Container for worker crashed with OOMKilled (exit code 137)",
        action_name="restart_container",
        target="container.worker",
        params={"target": "container.worker"},
        confidence=0.96,
        payload={
            "rationale": "Deterministic runbook matched OOMKilled exitCode 137 on root service worker",
            "evidence_ids": [ev_res_1.id, ev_res_2.id],
            "duration_seconds": 124,
            "verification": "Stable (120s stability window passed)",
        },
    )
    store.save_verified_outcome(
        outcome_id="out-res-01",
        incident_id=inc_resolved.id,
        action_name="restart_container",
        target="container.worker",
        template_ids=["tpl-oom-137"],
        services=["worker", "web"],
        changes=[],
        metrics_pattern=["oom_kill"],
        stable=True,
        payload={"tier": "D2_RUNBOOK", "duration_seconds": 124},
        fingerprint="fp-worker-oom-137",
    )
    # Additional historical outcomes so "how incidents were resolved" strip shows rules, retrieval, local LLM, human
    store.save_verified_outcome(
        outcome_id="out-res-02",
        incident_id="inc-hist-memory-02",
        action_name="restart_container",
        target="container.worker",
        template_ids=["tpl-oom-137"],
        services=["worker"],
        changes=[],
        metrics_pattern=["oom_kill"],
        stable=True,
        payload={"tier": "D1_MEMORY", "duration_seconds": 121},
        fingerprint="fp-worker-oom-137-b",
    )
    store.save_verified_outcome(
        outcome_id="out-res-03",
        incident_id="inc-hist-llm-03",
        action_name="rotate_logs",
        target="file.worker_log",
        template_ids=["tpl-disk-warn"],
        services=["worker"],
        changes=[],
        metrics_pattern=["disk_high"],
        stable=True,
        payload={"tier": "D3_LOCAL_LLM", "duration_seconds": 128},
        fingerprint="fp-worker-log-rot",
    )
    store.save_verified_outcome(
        outcome_id="out-res-04",
        incident_id="inc-hist-human-04",
        action_name="restart_service",
        target="database",
        template_ids=["tpl-pg-conn"],
        services=["database", "web"],
        changes=[],
        metrics_pattern=["tcp_refused"],
        stable=True,
        payload={"tier": "HUMAN", "duration_seconds": 140},
        fingerprint="fp-db-restart-human",
    )
    postmortem_md = (
        "# Incident Postmortem: inc-resolved-01\n\n"
        "- **Status**: Resolved (Verified Stable)\n"
        "- **Root Cause Service**: `worker` (downstream impact on `web`)\n"
        "- **Diagnosis Tier**: `D2_RUNBOOK` (confidence `0.96`)\n"
        "- **Action Executed**: `restart_container` on `container.worker`\n"
        "- **Verification**: Stability window passed (`120s / 120s`, 0 new alerts)\n"
        "- **Total Recovery Duration**: `124s`\n\n"
        "## Timeline\n"
        "1. `T-42m`: `container_logs` reported `fatal: container exited with code 137 OOMKilled` on `worker`.\n"
        "2. `T-41m30s`: `http_probe` on `web` degraded due to upstream `worker` timeout.\n"
        "3. `T-41m25s`: Correlator identified `worker` as root candidate via dependency graph (`nginx -> web -> worker`).\n"
        "4. `T-41m20s`: Policy authorized `restart_container` on `container.worker`.\n"
        "5. `T-39m16s`: Stability verifier confirmed recovery across 120s window.\n"
    )
    store.save_postmortem(
        inc_resolved.id,
        postmortem_md,
        {
            "action": "restart_container",
            "target": "container.worker",
            "verification_stable": True,
            "duration_seconds": 124,
            "tier": "D2_RUNBOOK",
        },
    )

    # Record the completed action in `actions` table (recent enough to trigger a live cooldown on container.worker!)
    with store.connection:
        store.connection.execute(
            "INSERT INTO actions VALUES (?,?,?,?,?,?,?,?)",
            (
                "act-verified-01",
                inc_resolved.id,
                "restart_container",
                "container.worker",
                "digest-verified-01",
                (now - timedelta(minutes=1)).isoformat(),
                1,
                "success",
            ),
        )
    store.audit("policy", "authorized", "final authorization decision for container.worker")
    store.audit("act-verified-01", "verified_success", "stability passed (120s)")

    if preset in ("all_clear", "learning"):
        # In all_clear or calm learning state, keep only historical resolved incident, no open incidents
        store.audit("system", "all_clear", "all monitored services healthy")
        return config, store

    # 2. Dry-run incident (inc-dryrun-02): handled in dry-run, not yet acted on -> "would have auto-executed"
    ev_dry_1 = Event(
        id="ev-dry-01",
        timestamp=now - timedelta(minutes=8),
        kind=Kind.ALERT,
        service="worker",
        source="container_logs",
        severity="error",
        evidence="fatal: container exited with code 137 OOMKilled (worker queue shard 2)",
        template_id="tpl-oom-137",
        attributes={"reason": "OOMKilled"},
    )
    ev_dry_2 = Event(
        id="ev-dry-02",
        timestamp=now - timedelta(minutes=7, seconds=45),
        kind=Kind.LOG,
        service="worker",
        source=str(ws_dir / "worker.log"),
        severity="warning",
        evidence=ev_adv.evidence,
        template_id="tpl-adv-01",
        attributes={"note": "redacted untrusted log line"},
    )
    store.event(ev_dry_1)
    store.event(ev_dry_2)
    inc_dry = Incident(
        id="inc-dryrun-02",
        opened_at=now - timedelta(minutes=8),
        state=State.INVESTIGATING,
        services=["worker", "web"],
        root_candidates=["worker"],
        downstream=["web"],
        event_ids=[ev_dry_1.id, ev_dry_2.id],
        flap_count=0,
    )
    store.save_incident(inc_dry)
    store.save_hypothesis(
        hypothesis_id="hyp-dry-01",
        incident_id=inc_dry.id,
        tier="D2_RUNBOOK",
        root_cause="Container for worker crashed or exited abnormally",
        action_name="restart_container",
        target="container.worker",
        params={"target": "container.worker"},
        confidence=0.95,
        payload={
            "rationale": "Observed container exit/failure signals on worker (root candidate)",
            "evidence_ids": [ev_dry_1.id],
            "dry_run_handled": True,
        },
    )
    store.save_hypothesis(
        hypothesis_id="hyp-dry-02",
        incident_id=inc_dry.id,
        tier="D1_MEMORY",
        root_cause="Historical match: worker OOMKilled recovery via container restart",
        action_name="restart_container",
        target="container.worker",
        params={"target": "container.worker"},
        confidence=0.91,
        payload={
            "rationale": "BM25 outcome similarity 0.91 with incident inc-resolved-01",
            "evidence_ids": [ev_dry_1.id],
            "dry_run_handled": True,
        },
    )
    store.audit("policy", "dry_run", "advisory decision: would have auto-executed restart_container on container.worker")
    store.audit("policy", "cooldown", "advisory refusal: restart_container on container.worker cooling down")

    # 3. Pending approval incident (inc-approval-03): critical database service with 2 staged proposals
    ev_db_1 = Event(
        id="ev-db-01",
        timestamp=now - timedelta(minutes=3),
        kind=ev_db.kind,
        service="database",
        source="tcp_probe",
        severity="error",
        evidence="health probe connection timed out on postgresql.service (127.0.0.1:5432)",
        template_id="tpl-db-timeout",
        attributes={"healthy": False, "port": 5432},
    )
    ev_db_2 = Event(
        id="ev-db-02",
        timestamp=now - timedelta(minutes=2, seconds=50),
        kind=Kind.HEALTH,
        service="web",
        source="http_probe",
        severity="error",
        evidence="HTTP 503 Service Unavailable: upstream database pool exhausted",
        template_id="tpl-web-503",
        attributes={"healthy": False, "status_code": 503},
    )
    ev_db_3 = Event(
        id="ev-db-03",
        timestamp=now - timedelta(minutes=2, seconds=40),
        kind=Kind.HEALTH,
        service="nginx",
        source="http_probe",
        severity="warning",
        evidence="nginx upstream web returned 503",
        template_id="tpl-nginx-503",
        attributes={"healthy": False},
    )
    store.event(ev_db_1)
    store.event(ev_db_2)
    store.event(ev_db_3)
    inc_appr = Incident(
        id="inc-approval-03",
        opened_at=now - timedelta(minutes=3),
        state=State.ESCALATED,
        services=["nginx", "web", "database"],
        root_candidates=["database"],
        downstream=["web", "nginx"],
        event_ids=[ev_db_1.id, ev_db_2.id, ev_db_3.id],
        flap_count=1,
    )
    store.save_incident(inc_appr)
    store.save_hypothesis(
        hypothesis_id="hyp-appr-01",
        incident_id=inc_appr.id,
        tier="D2_RUNBOOK",
        root_cause="Root service database health check failing; downstream web and nginx degraded",
        action_name="restart_service",
        target="database",
        params={"target": "database"},
        confidence=0.95,
        payload={
            "rationale": "Dependency graph traces nginx -> web -> database; database is CRITICAL and requires operator approval",
            "evidence_ids": [ev_db_1.id, ev_db_2.id, ev_db_3.id],
        },
    )
    store.save_hypothesis(
        hypothesis_id="hyp-appr-02",
        incident_id=inc_appr.id,
        tier="D2_RUNBOOK",
        root_cause="Nginx upstream pool stale after database degradation",
        action_name="reload_nginx",
        target="nginx",
        params={"target": "nginx"},
        confidence=0.92,
        payload={
            "rationale": "Secondary mitigation to reload nginx upstream workers after database recovery",
            "evidence_ids": [ev_db_3.id],
        },
    )

    prop_db = Proposal(
        incident_id=inc_appr.id,
        name="restart_service",
        params={"target": "database"},
        expected_revision="unit:postgresql.service:failed",
        confidence=0.95,
    )
    prop_nginx = Proposal(
        incident_id=inc_appr.id,
        name="reload_nginx",
        params={"target": "nginx"},
        expected_revision="unit:nginx.service:active",
        confidence=0.92,
    )
    state.stage_pending(prop_db)
    state.stage_pending(prop_nginx)
    store.audit("policy", "critical_approval_required", f"staged {proposal_digest(prop_db)[:12]} for critical target database")
    store.audit("policy", "approval_required", f"staged {proposal_digest(prop_nginx)[:12]} for approval-tier reload_nginx")

    # Record kill switch history in audit_log
    store.audit("sre_oncall", "kill_switch", "True")
    store.audit("sre_oncall", "kill_switch", "False")

    if preset == "killed":
        state.kill_switch(True, "demo_operator")
        store.audit("policy", "kill_switch", "refused restart_container: global kill switch is engaged")
    elif preset == "circuit_open":
        with store.connection:
            store.connection.execute(
                "INSERT INTO actions VALUES (?,?,?,?,?,?,?,?)",
                (
                    "act-interrupted-09",
                    inc_dry.id,
                    "restart_container",
                    "container.worker",
                    "digest-interrupted-09",
                    (now - timedelta(minutes=2)).isoformat(),
                    1,
                    "executing",
                ),
            )
            store.connection.execute(
                "UPDATE safety_control SET failures=3, circuit_open=1 WHERE id=1"
            )
        store.audit("policy", "circuit_breaker", "refused: circuit breaker open (3 consecutive failures / unresolved action act-interrupted-09)")

    return config, store

