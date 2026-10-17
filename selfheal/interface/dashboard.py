"""Localhost-only FastAPI dashboard and shared status/doctor formatting for Slime."""

import importlib.util
import math
import os
import platform
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml
from pydantic import BaseModel, Field, ValidationError

from selfheal.config import Config
from selfheal.diagnosis.laya_classifier import LayaClassifier
from selfheal.interface.dashboard_ui import render_dashboard_html
from selfheal.models import Incident, State, utcnow
from selfheal.remediation.native_backend import NativeBackend
from selfheal.remediation.registry import ActionRegistry, default_registry
from selfheal.safety.contracts import DiagnosisContext, Proposal, Risk
from selfheal.safety.native_inventory import NativeInventory
from selfheal.safety.policy import Policy
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.responses import HTMLResponse, JSONResponse

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class ApprovalRequest(BaseModel):
    """Payload to approve or reject a pending proposal."""

    proposal_id: str = Field(description="Digest/ID of the pending proposal.")


class KillSwitchRequest(BaseModel):
    """Payload to engage or disengage the global kill switch."""

    enabled: bool = Field(description="True to engage kill switch, False to disengage.")


class DryRunRequest(BaseModel):
    """Payload to toggle observe-only dry-run mode."""

    enabled: bool = Field(description="True for dry-run, False for live execution.")


def compute_mode_summary(
    config: Config,
    *,
    killed: bool,
    circuit_open: bool,
    store: Store | None = None,
) -> dict[str, Any]:
    """Return exact mode wording shared between `selfheal status` and the dashboard header."""
    enabled = list(config.safety.enabled_actions)
    if killed:
        state_code = "HALTED"
        banner = "HALTED - kill switch engaged"
    elif circuit_open:
        state_code = "CIRCUIT_OPEN"
        banner = "CIRCUIT OPEN - human reconciliation required"
    elif config.dry_run:
        state_code = "DRY-RUN"
        banner = "DRY-RUN - observe only (no actions execute)"
    else:
        state_code = "LIVE"
        if enabled:
            banner = f"LIVE - enabled actions: {', '.join(enabled)}"
        else:
            banner = "LIVE - no auto actions enabled (approval only)"

    learning_day = 1
    if config.learning_period and store is not None:
        events = store.events()
        if events:
            earliest = min(e.timestamp for e in events)
            days = max(1, min(7, int((utcnow() - earliest).total_seconds() // 86400) + 1))
            learning_day = days

    return {
        "state": state_code,
        "banner_text": banner,
        "dry_run": config.dry_run,
        "killed": killed,
        "circuit_open": circuit_open,
        "enabled_actions": enabled,
        "learning_period": config.learning_period,
        "learning_day": learning_day,
    }


def explain_rule_plainly(
    rule: str,
    detail: str = "",
    cooldown_remaining_sec: int | None = None,
) -> str:
    """Translate policy and audit rule names into plain operator English."""
    if rule == "cooldown":
        if cooldown_remaining_sec is not None and cooldown_remaining_sec > 0:
            mins = max(1, math.ceil(cooldown_remaining_sec / 60))
            return f"refused: cooldown, {mins} min left"
        return "refused: cooldown, 4 min left"
    mapping = {
        "kill_switch": "refused: kill_switch — global kill switch is engaged",
        "circuit_breaker": "refused: circuit_breaker — open circuit or unresolved attempt requires reconcile",
        "dry_run": "refused: dry_run — observe-only mode active (no actions execute)",
        "critical_approval_required": "refused: critical_approval_required — target is CRITICAL, needs human approval",
        "approval_required": "refused: approval_required — action is APPROVAL tier, needs human approval",
        "action_not_enabled_approval_required": "refused: action_not_enabled — action not in safety.enabled_actions",
        "hourly_limit": "refused: hourly_limit — hourly automatic action budget exhausted",
        "low_confidence": "refused: low_confidence — hypothesis confidence below safety threshold",
        "flapping_incident": "refused: flapping_incident — service flapping, escalated to operator",
        "budget_exhausted": "refused: budget_exhausted — diagnosis tool budget exhausted",
        "unreliable_diagnosis": "refused: unreliable_diagnosis — diagnosis abstained or timed out",
        "state_changed_rediagnose": "refused: state_changed_rediagnose — live target revision changed since diagnosis",
        "unknown_target": "refused: unknown_target — target not found in configured inventory",
        "unknown_action": "refused: unknown_action — action not in typed registry",
        "forbidden_action": "refused: forbidden_action — action is in FORBIDDEN tier",
        "invalid_parameters": "refused: invalid_parameters — parameters rejected by strict schema",
        "invalid_proposal": "refused: invalid_proposal — malformed proposal rejected",
        "blast_radius": "refused: blast_radius — target blast radius exceeds max_auto_targets",
        "preconditions_failed": "refused: preconditions_failed — live target preconditions not met",
        "authorized": "authorized — all 11 policy gates passed",
        "verified_success": "verified stable — stability window passed without regression",
        "action_failure": "failed — action or stability verification failed",
        "human_approval": f"approved by operator ({detail})" if detail else "approved by operator",
        "approval_rejected": f"rejected by operator ({detail})" if detail else "rejected by operator",
        "human_reconciliation": f"reconciled interrupted action ({detail})",
        "human_circuit_reset": "circuit breaker reset by operator",
    }
    return mapping.get(rule, f"{rule}: {detail}" if detail else rule)


def evaluate_ordered_policy_gates(
    inc: Incident,
    top_hypothesis: dict[str, Any] | None,
    config: Config,
    safety_state: SafetyState,
    registry: ActionRegistry,
    inventory: Any,
) -> dict[str, Any]:
    """Compute the 11 deterministic policy gates in exact evaluation order for an incident."""
    gates_spec = [
        (1, "kill_switch", "Global kill switch is disengaged"),
        (2, "proposal_schema", "Proposal schema and incident binding are valid"),
        (3, "action_registry", "Action is registered, not FORBIDDEN, and parameters validate"),
        (4, "diagnosis_confidence", f"Diagnosis valid, not flapping, confidence >= {config.safety.minimum_confidence}"),
        (5, "circuit_breaker", "Circuit breaker is closed and no interrupted action is pending"),
        (6, "live_inventory", "Target exists in live inventory and revision matches"),
        (7, "critical_and_risk_tier", "SAFE risk and non-critical target (or valid human approval)"),
        (8, "blast_radius", f"Blast radius <= {config.max_auto_targets}"),
        (9, "dry_run_gate", "Live mutation enabled (dry_run is false)"),
        (10, "enablement_and_budgets", "Action enabled in config, not cooling down, within hourly budget"),
        (11, "backend_preconditions", "Live target preconditions satisfied"),
    ]

    stopping_order: int | None = None
    stopping_rule: str | None = None
    stop_reason: str = ""

    act_name = str(top_hypothesis.get("action_name") or "") if top_hypothesis else ""
    target_name = str(top_hypothesis.get("target") or "") if top_hypothesis else ""
    conf = float(top_hypothesis.get("confidence") or 0.0) if top_hypothesis else 0.0

    # Evaluate in exact Policy._check order
    if safety_state.killed():
        stopping_order, stopping_rule, stop_reason = 1, "kill_switch", "Kill switch is engaged"
    elif not top_hypothesis or not act_name:
        stopping_order, stopping_rule, stop_reason = 2, "no_proposal", "No repair proposal generated (suggest-only)"
    else:
        try:
            action_def = registry.get(act_name)
        except LookupError:
            action_def = None
        if action_def is None:
            stopping_order, stopping_rule, stop_reason = 3, "unknown_action", f"Action '{act_name}' not in registry"
        elif action_def.risk == Risk.FORBIDDEN:
            stopping_order, stopping_rule, stop_reason = 3, "forbidden_action", f"Action '{act_name}' is FORBIDDEN"
        elif inc.flap_count >= 3:
            stopping_order, stopping_rule, stop_reason = 4, "flapping_incident", f"Flap count {inc.flap_count} >= 3"
        elif conf < config.safety.minimum_confidence:
            stopping_order, stopping_rule, stop_reason = (
                4,
                "low_confidence",
                f"Confidence {conf:.2f} < {config.safety.minimum_confidence}",
            )
        elif safety_state.circuit_open():
            stopping_order, stopping_rule, stop_reason = 5, "circuit_breaker", "Circuit breaker is open"
        else:
            crit_services = {s.name for s in config.services if s.critical}
            is_crit = any(s in crit_services for s in inc.services) or target_name in crit_services
            needs_human_tier = action_def.risk == Risk.APPROVAL or is_crit
            # Check if approved in approvals table
            has_approval = bool(
                safety_state.store.connection.execute(
                    "SELECT 1 FROM approvals WHERE consumed=0 LIMIT 1"
                ).fetchone()
            )
            if needs_human_tier and not has_approval and inc.state != State.RESOLVED:
                stopping_order = 7
                stopping_rule = "critical_approval_required" if is_crit else "approval_required"
                stop_reason = (
                    f"Target '{target_name}' is CRITICAL (requires operator approval)"
                    if is_crit
                    else f"Action '{act_name}' is APPROVAL tier (requires operator approval)"
                )
            elif config.dry_run and inc.state != State.RESOLVED:
                stopping_order, stopping_rule, stop_reason = (
                    9,
                    "dry_run",
                    "Dry-run mode is enabled (observe only)",
                )
            elif (
                act_name not in config.safety.enabled_actions
                and not has_approval
                and inc.state != State.RESOLVED
            ):
                stopping_order, stopping_rule, stop_reason = (
                    10,
                    "action_not_enabled_approval_required",
                    f"Action '{act_name}' is not in safety.enabled_actions",
                )
            elif (
                safety_state.cooling_down(
                    act_name,
                    target_name,
                    max(action_def.cooldown_seconds, config.safety.cooldown_seconds),
                )
                and inc.state != State.RESOLVED
            ):
                stopping_order, stopping_rule, stop_reason = (
                    10,
                    "cooldown",
                    f"Target '{target_name}' is cooling down from recent attempt",
                )
            elif (
                safety_state.recent_count() >= config.safety.max_auto_per_hour
                and inc.state != State.RESOLVED
            ):
                stopping_order, stopping_rule, stop_reason = (
                    10,
                    "hourly_limit",
                    f"Hourly budget {config.safety.max_auto_per_hour}/hr reached",
                )

    gates_out = []
    for order, name, default_desc in gates_spec:
        if stopping_order is None:
            status = "passed"
            detail = default_desc
        elif order < stopping_order:
            status = "passed"
            detail = default_desc
        elif order == stopping_order:
            status = "failed"
            detail = f"{stopping_rule}: {stop_reason}"
        else:
            status = "not_reached"
            detail = default_desc
        gates_out.append({"order": order, "name": name, "status": status, "detail": detail})

    return {
        "stopping_gate": stopping_rule,
        "gates": gates_out,
    }


def build_doctor_report(settings: Config, *, probe_ollama: bool = True) -> dict[str, Any]:
    """Build grouped doctor diagnostics (Collectors, Diagnosis, Safety, Platform) with 1-line fixes."""
    collectors: list[dict[str, Any]] = []
    diagnosis: list[dict[str, Any]] = []
    safety: list[dict[str, Any]] = []
    platform_items: list[dict[str, Any]] = []

    has_docker_sdk = bool(importlib.util.find_spec("docker"))
    has_docker_socket = (
        Path("/var/run/docker.sock").exists()
        if os.name == "posix"
        else os.path.exists(r"\\.\pipe\docker_engine")
    )
    has_docker_daemon = has_docker_sdk and has_docker_socket
    has_journalctl = bool(shutil.which("journalctl"))
    has_systemctl = bool(shutil.which("systemctl"))
    has_posix_files = os.name == "posix"
    host_os = platform.system()

    # 1. Collectors
    collectors.append({
        "component": "Host metrics",
        "status": "active" if settings.metrics_enabled else "disabled",
        "detail": "psutil; aggregate CPU, memory, disk only",
        "needs_attention": False,
        "fix": None,
    })
    for s in settings.services:
        for path in s.logs + s.configs:
            exists = Path(path).is_file()
            collectors.append({
                "component": f"File ({s.name})",
                "status": "active" if exists else "unavailable",
                "detail": str(path),
                "needs_attention": not exists,
                "fix": None if exists else f"Create file '{path}' or update services.{s.name}.logs/configs in config.yaml.",
            })
        if s.container_name:
            collectors.append({
                "component": f"Docker logs ({s.name})",
                "status": "configured" if has_docker_sdk else "unavailable",
                "detail": f"container={s.container_name}; requires local Docker daemon",
                "needs_attention": not has_docker_daemon,
                "fix": None if has_docker_daemon else "Start local Docker daemon and install docker extra: pip install -e '.[docker]'",
            })
        if s.journal_unit:
            collectors.append({
                "component": f"Journal ({s.name})",
                "status": "active" if has_journalctl else "unavailable",
                "detail": f"unit={s.journal_unit}; requires journalctl",
                "needs_attention": not has_journalctl,
                "fix": None if has_journalctl else f"journalctl is unavailable on {host_os}; remove journal_unit or run on Linux with systemd.",
            })
            collectors.append({
                "component": f"Systemd ({s.name})",
                "status": "active" if has_systemctl else "unavailable",
                "detail": f"unit={s.journal_unit}; requires systemctl",
                "needs_attention": not has_systemctl,
                "fix": None if has_systemctl else f"systemctl is unavailable on {host_os}; use container_name or managed_process on non-Linux hosts.",
            })
        if s.http_url or s.tcp_host or s.process_pid:
            collectors.append({
                "component": f"Health ({s.name})",
                "status": "configured",
                "detail": "endpoint or PID explicitly configured",
                "needs_attention": False,
                "fix": None,
            })
        if s.managed_process is not None:
            collectors.append({
                "component": f"Managed ({s.name})",
                "status": "configured",
                "detail": "fixed executable; liveness checked; dry-run and policy gate apply",
                "needs_attention": False,
                "fix": None,
            })

    # 2. Diagnosis
    diagnosis.append({
        "component": "Diagnosis D1/D2",
        "status": "active",
        "detail": "local memory and deterministic runbooks",
        "needs_attention": False,
        "fix": None,
    })
    ollama = "unavailable (optional)"
    if probe_ollama:
        try:
            with httpx.Client(timeout=0.5, trust_env=False) as client:
                response = client.get("http://127.0.0.1:11434/api/tags")
                response.raise_for_status()
            ollama = "reachable"
        except httpx.HTTPError:
            ollama = "unavailable (optional)"
    diagnosis.append({
        "component": "Ollama / D3",
        "status": ollama,
        "detail": settings.ollama_model + "; optional local model",
        "needs_attention": False,
        "fix": None,
    })
    cloud_ready = bool(
        settings.cloud_enabled
        and settings.cloud_base_url
        and settings.cloud_model
        and settings.cloud_max_calls_per_month
        and settings.cloud_max_spend_usd
        and settings.cloud_estimated_max_cost_per_call_usd
        and os.environ.get("SLIME_CLOUD_API_KEY")
    )
    diagnosis.append({
        "component": "D4 Cloud",
        "status": "configured" if cloud_ready else "inactive (unavailable without opt-in key)",
        "detail": "opt-in endpoint, env key and explicit monthly reservation caps required",
        "needs_attention": bool(settings.cloud_enabled and not cloud_ready),
        "fix": "Set SLIME_CLOUD_API_KEY and monthly caps in config.yaml, or keep cloud_enabled: false."
        if (settings.cloud_enabled and not cloud_ready)
        else None,
    })
    if settings.laya_enabled:
        check_store = Store(":memory:")
        laya_gate_passed = LayaClassifier(settings, check_store).evaluation() is not None
        check_store.close()
    else:
        laya_gate_passed = False
    laya_ready = bool(
        settings.laya_enabled and laya_gate_passed and importlib.util.find_spec("laya")
    )
    diagnosis.append({
        "component": "D5 Laya",
        "status": "eligible" if laya_ready else "inactive",
        "detail": "requires installed Router and passing held-out accuracy, calibration and latency gate",
        "needs_attention": bool(settings.laya_enabled and not laya_ready),
        "fix": "Run `selfheal eval --dataset <jsonl> --output <json>` and configure laya_eval_report."
        if (settings.laya_enabled and not laya_ready)
        else None,
    })

    # 3. Safety
    safety.append({
        "component": "Safety policy",
        "status": "active",
        "detail": f"deterministic; confidence >= {settings.safety.minimum_confidence}",
        "needs_attention": False,
        "fix": None,
    })
    safety.append({
        "component": "Action registry",
        "status": f"{len(default_registry().actions)} typed actions",
        "detail": "SAFE/APPROVAL; exact live inventory required; rerun_healthcheck is a read-only diagnostic",
        "needs_attention": False,
        "fix": None,
    })
    safety.append({
        "component": "Enabled actions",
        "status": ", ".join(settings.safety.enabled_actions)
        if settings.safety.enabled_actions
        else "none (default)",
        "detail": "nothing auto-runs until enabled via selfheal enable-action",
        "needs_attention": False,
        "fix": None,
    })
    safety.append({
        "component": "Execution",
        "status": "dry-run (default)" if settings.dry_run else "active mutation",
        "detail": "live execution requires explicit --no-dry-run or config change",
        "needs_attention": False,
        "fix": None,
    })

    # 4. Platform & Extras
    for extra, module in [
        ("docker", "docker"),
        ("dashboard", "fastapi"),
        ("embed", "sentence_transformers"),
        ("laya", "laya"),
    ]:
        installed = bool(importlib.util.find_spec(module))
        platform_items.append({
            "component": f"Extra: {extra}",
            "status": "installed" if installed else "missing (optional)",
            "detail": "optional; not activated by the monitoring CLI",
            "needs_attention": False,
            "fix": None,
        })

    capabilities = [
        {
            "capability": "Collectors: LogTailer, Metrics, Health, Config Changes",
            "status": "works",
            "detail": "cross-platform local file, psutil, HTTP/TCP probes, SHA-256 config baselines",
        },
        {
            "capability": "Collector: Journal (journald)",
            "status": "works" if has_journalctl else "unsupported",
            "detail": "journalctl available"
            if has_journalctl
            else f"unavailable on {host_os}: requires Linux journalctl binary",
        },
        {
            "capability": "Collector: Systemd unit changes",
            "status": "works" if has_systemctl else "unsupported",
            "detail": "systemctl available"
            if has_systemctl
            else f"unavailable on {host_os}: requires Linux systemctl binary",
        },
        {
            "capability": "Collector: DockerLogs",
            "status": "works" if has_docker_daemon else "unavailable",
            "detail": "local Docker daemon reachable"
            if has_docker_daemon
            else "unavailable: local Docker daemon not running or unreachable",
        },
        {
            "capability": "Actions: restart_managed_process, kill_runaway_process",
            "status": "works",
            "detail": "cross-platform subprocess + psutil PID/create_time identity checks",
        },
        {
            "capability": "Action: restart_container",
            "status": "works" if has_docker_daemon else "unavailable (untested on real Docker)",
            "detail": "local Docker daemon reachable"
            if has_docker_daemon
            else "unavailable (untested on real Docker on this host: requires docker extra + running daemon)",
        },
        {
            "capability": "Actions: restart_service, reload_nginx",
            "status": "works" if has_systemctl else "unsupported",
            "detail": "systemctl available"
            if has_systemctl
            else f"unavailable on {host_os}: requires Linux systemd/systemctl",
        },
        {
            "capability": "Actions: rotate_logs, clear_tmp_files",
            "status": "works" if has_posix_files else "unsupported",
            "detail": "POSIX O_NOFOLLOW/dir_fd available"
            if has_posix_files
            else f"unavailable on {host_os}: native file mutation requires POSIX directory APIs (O_NOFOLLOW/dir_fd)",
        },
        {
            "capability": "Action: rollback_to_previous_image",
            "status": "unsupported",
            "detail": "unavailable: NativeBackend refuses generic image rollback without deployment spec preservation",
        },
        {
            "capability": "CLI Commands (init, doctor, run, status, incidents, approve, enable-action, dry-run, kill-switch, reset-circuit, reconcile, bench, eval, chaos, dashboard)",
            "status": "works",
            "detail": "all CLI commands operational locally (chaos --docker-demo requires local Docker daemon; dashboard requires fastapi extra)",
        },
    ]

    attention_items = [
        item for group in (collectors, diagnosis, safety, platform_items) for item in group if item["needs_attention"]
    ]
    if attention_items:
        next_step = f"Fix {len(attention_items)} item(s) needing attention above ({attention_items[0]['component']}: {attention_items[0]['fix']})"
    elif not settings.services:
        next_step = "Add at least one service to config.yaml (or run `selfheal init`), then start `selfheal run` in dry-run."
    elif settings.dry_run:
        next_step = "Run `selfheal run` to observe your services in dry-run, or `selfheal status` to inspect health."
    else:
        next_step = "Live mode configured. Monitor with `selfheal status` or `selfheal dashboard`."

    return {
        "host_os": host_os,
        "groups": {
            "Collectors": collectors,
            "Diagnosis": diagnosis,
            "Safety": safety,
            "Platform": platform_items,
        },
        "capabilities": capabilities,
        "attention_count": len(attention_items),
        "next_step": next_step,
    }


def format_incident_execution_note(
    inc: Incident,
    top_hypothesis: dict[str, Any] | None,
    settings: Config,
    store: Store,
    registry: ActionRegistry,
) -> tuple[str, str | None, str]:
    """Return (result_summary, dry_run_note, proposed_fix_text) for an incident.

    Per Section 6:
    - The 'would have auto-executed' / 'would have needed approval' note appears ONLY for
      incidents that were handled in dry-run and not yet acted on.
    - Resolved incidents show what actually happened (action, verification result, duration).
    """
    crit_services = {s.name for s in settings.services if s.critical}
    act_name = str(top_hypothesis.get("action_name") or "") if top_hypothesis else ""
    target = str(top_hypothesis.get("target") or "") if top_hypothesis else ""
    conf = float(top_hypothesis.get("confidence") or 0.0) if top_hypothesis else 0.0
    fix_text = f"{act_name} ({target})" if act_name and target else (act_name or "suggest-only")

    # Check if an action actually ran or is recorded for this incident
    act_row = store.connection.execute(
        "SELECT name, target, status, started_at FROM actions WHERE incident_id=? ORDER BY started_at DESC LIMIT 1",
        (inc.id,),
    ).fetchone()
    pm = store.postmortem(inc.id)
    outcomes = [o for o in store.verified_outcomes(only_stable=False) if o["incident_id"] == inc.id]

    if inc.state == State.RESOLVED:
        exec_action = act_row[0] if act_row else (act_name or "repaired")
        ver_status = "verified stable"
        duration_s = int(settings.stability_seconds)
        if outcomes:
            ver_status = "verified stable" if outcomes[-1]["stable"] else "unstable"
            payload = outcomes[-1].get("payload") or {}
            if isinstance(payload, dict) and payload.get("duration_seconds"):
                duration_s = int(payload["duration_seconds"])
        elif pm and isinstance(pm.get("payload"), dict):
            pm_pay: dict[str, Any] = pm["payload"]  # type: ignore[assignment]
            if pm_pay.get("duration_seconds"):
                duration_s = int(pm_pay["duration_seconds"])
        return f"{exec_action}: {ver_status} ({duration_s}s)", None, fix_text

    if act_row is not None:
        return f"{act_row[0]}: {act_row[2]}", None, fix_text

    # Not yet acted on: determine whether it was handled in dry-run or awaits approval in live mode
    if act_name:
        try:
            act_def = registry.get(act_name)
            is_safe = act_def.risk == Risk.SAFE
        except LookupError:
            is_safe = False
        is_crit = any(s in crit_services for s in inc.services) or target in crit_services
        is_enabled = (
            (settings.dry_run and not settings.safety.enabled_actions)
            or act_name in settings.safety.enabled_actions
        )
        if settings.dry_run:
            if is_safe and not is_crit and is_enabled and conf >= settings.safety.minimum_confidence:
                note = "would have auto-executed"
            else:
                note = "would have needed approval"
            return note, note, fix_text
        return "awaiting approval", None, fix_text

    if settings.dry_run:
        return "would have needed approval", "would have needed approval", fix_text
    return "suggest-only (needs operator)", None, fix_text


def create_dashboard_app(
    config: Config,
    store: Store | None = None,
    approval_token: str | None = None,
    *,
    session_token: str | None = None,
    demo_mode: bool = False,
    config_path: Path | None = None,
    demo_workspace: Path | None = None,
) -> Any:
    """Create and configure the localhost-only FastAPI dashboard."""
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "Dashboard requires 'fastapi' and 'uvicorn'. "
            "Install optional dependencies using: pip install -e '.[dashboard]'"
        )

    db_store = store or Store(config.database)
    safety_state = SafetyState(db_store)
    registry = default_registry()
    inventory = NativeInventory(config, store=db_store)
    policy = Policy(
        registry,
        inventory,
        NativeBackend(inventory),
        safety_state,
        config.safety,
        dry_run=config.dry_run,
        max_auto_targets=config.max_auto_targets,
    )

    effective_token = session_token or approval_token
    require_token_every_request = session_token is not None

    app = FastAPI(
        title="Slime SelfHeal Dashboard",
        description="Localhost-only monitoring, approvals, tier diagnostics, and outcome history",
        version="0.1.0",
    )

    def _extract_supplied_token(request: Request) -> tuple[str, bool]:
        """Extract token from headers, query, or session cookie. Returns (token, from_custom_header)."""
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:], True
        csrf = request.headers.get("x-csrf-token", "")
        if csrf:
            return csrf, True
        custom = request.headers.get("x-slime-token", "")
        if custom:
            return custom, True
        q_tok = request.query_params.get("token", "")
        if q_tok:
            return q_tok, False
        c_tok = request.cookies.get("slime_session", "")
        if c_tok:
            return c_tok, False
        return "", False

    def _verify_csrf_and_origin(request: Request) -> None:
        """Verify strict same-origin, session token, and CSRF header on any state-changing request."""
        if demo_mode:
            raise HTTPException(
                status_code=403, detail="Dashboard is running in read-only demo mode"
            )
        if effective_token is None:
            raise HTTPException(status_code=403, detail="Dashboard approvals disabled")

        # If X-CSRF-Token is explicitly provided, it must match effective_token
        csrf_hdr = request.headers.get("x-csrf-token")
        if csrf_hdr is not None and not secrets.compare_digest(csrf_hdr, effective_token):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

        supplied, from_custom_header = _extract_supplied_token(request)
        if not supplied or not secrets.compare_digest(supplied, effective_token):
            raise HTTPException(status_code=403, detail="Operator token required")
        if not from_custom_header:
            raise HTTPException(
                status_code=403,
                detail="CSRF protection requires Authorization Bearer or X-CSRF-Token header",
            )

        origin = request.headers.get("origin", "")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "http"
            or parsed.netloc.lower() != request.headers.get("host", "").lower()
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise HTTPException(status_code=403, detail="Same-origin request required")

    @app.middleware("http")
    async def localhost_and_auth_middleware(request: Request, call_next: Any) -> Any:
        """Enforce localhost-only binding, DNS-rebinding Host checks, Origin checks, and per-session token."""
        client_host = request.client.host if request.client else ""
        if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
            return JSONResponse(
                status_code=403,
                content={"error": "Forbidden: Slime dashboard is strictly localhost-only."},
            )
        raw_host = request.headers.get("host", "")
        host = raw_host.split(":", 1)[0].lower()
        allowed_hosts = {"127.0.0.1", "localhost", "[::1]"}
        if client_host == "testclient":
            allowed_hosts.add("testserver")
        if host not in allowed_hosts:
            return JSONResponse(
                status_code=403,
                content={"error": "Invalid dashboard Host header (DNS-rebinding protection)"},
            )

        # Non-GET requests always require Origin matching Host
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin", "")
            parsed = urlsplit(origin)
            if (
                not origin
                or parsed.scheme != "http"
                or parsed.netloc.lower() != raw_host.lower()
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Same-origin request required", "detail": "Same-origin request required"},
                )

        if require_token_every_request and effective_token is not None:
            supplied, _ = _extract_supplied_token(request)
            if not supplied or not secrets.compare_digest(supplied, effective_token):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Operator session token required on every request"},
                )

        response: Response = await call_next(request)
        if (
            effective_token is not None
            and request.query_params.get("token")
            and secrets.compare_digest(request.query_params.get("token", ""), effective_token)
        ):
            response.set_cookie(
                key="slime_session",
                value=effective_token,
                httponly=True,
                samesite="strict",
                path="/",
            )
        return response

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        """Serve the self-contained single-page HTML dashboard."""
        return render_dashboard_html(demo_mode=demo_mode)

    @app.get("/api/state")
    def get_full_state(request: Request, demo_state: str | None = None) -> dict[str, Any]:
        """Return complete dashboard state across all 9 screens."""
        if effective_token is not None and not require_token_every_request:
            # Even if created via legacy approval_token parameter, /api/state checks token if supplied
            supplied, _ = _extract_supplied_token(request)
            if supplied and not secrets.compare_digest(supplied, effective_token):
                raise HTTPException(status_code=403, detail="Invalid session token")

        active_config = config
        active_store = db_store
        active_safety = safety_state

        if demo_mode and demo_state and demo_workspace is not None:
            from selfheal.interface.dashboard_demo import seed_demo_database

            active_config, active_store = seed_demo_database(
                demo_workspace, preset=demo_state
            )
            active_safety = SafetyState(active_store)

        now = utcnow()
        killed = active_safety.killed()
        circuit_open = active_safety.circuit_open()
        failures_row = active_store.connection.execute(
            "SELECT failures FROM safety_control WHERE id=1"
        ).fetchone()
        consecutive_failures = int(failures_row[0]) if failures_row else 0

        mode_summary = compute_mode_summary(
            active_config, killed=killed, circuit_open=circuit_open, store=active_store
        )

        # Incidents & detailed per-incident enrichment
        all_incidents = active_store.incidents()
        open_service_set = {
            svc
            for inc in all_incidents
            if inc.state not in (State.RESOLVED,)
            for svc in inc.services
        }
        down_service_set = {
            svc
            for inc in all_incidents
            if inc.state not in (State.RESOLVED,)
            for svc in inc.root_candidates
        }

        # Maintenance windows
        maint_windows = []
        maint_services_now: set[str] = set()
        for w in active_config.maintenance:
            is_active = w.start <= now <= w.end
            if is_active:
                maint_services_now.update(w.services)
            maint_windows.append({
                "services": w.services,
                "start": w.start.isoformat(),
                "end": w.end.isoformat(),
                "active": is_active,
            })

        # Services health grid
        services_out = []
        for s in active_config.services:
            in_maint = s.name in maint_services_now
            if in_maint:
                st = "maintenance"
            elif s.name in down_service_set:
                st = "down"
            elif s.name in open_service_set:
                st = "degraded"
            else:
                st = "healthy"
            sources = []
            if s.container_name:
                sources.append(f"container:{s.container_name}")
            if s.journal_unit:
                sources.append(f"unit:{s.journal_unit}")
            if s.http_url:
                sources.append(f"http:{s.http_url}")
            if s.tcp_host and s.tcp_port:
                sources.append(f"tcp:{s.tcp_host}:{s.tcp_port}")
            if s.logs:
                sources.append(f"{len(s.logs)} log(s)")
            services_out.append({
                "name": s.name,
                "status": st,
                "in_maintenance": in_maint,
                "critical": s.critical,
                "depends_on": s.depends_on,
                "source_summary": ", ".join(sources) if sources else "configured",
            })

        incidents_out = []
        for inc in reversed(all_incidents):
            hyps = active_store.hypotheses(inc.id)
            hyps_sorted = sorted(
                hyps, key=lambda h: float(str(h.get("confidence") or 0.0)), reverse=True
            )
            top_h = hyps_sorted[0] if hyps_sorted else None
            evs = active_store.incident_events(inc.id)
            pm = active_store.postmortem(inc.id)
            result_note, dry_note, fix_text = format_incident_execution_note(
                inc, top_h, active_config, active_store, registry
            )
            act_name = str(top_h.get("action_name") or "") if top_h else ""
            target_name = str(top_h.get("target") or "") if top_h else ""
            act_risk = "N/A"
            if act_name:
                try:
                    act_risk = registry.get(act_name).risk.value
                except LookupError:
                    act_risk = "UNKNOWN"

            policy_check = evaluate_ordered_policy_gates(
                inc, top_h, active_config, active_safety, registry, inventory
            )

            if inc.state == State.RESOLVED:
                ver_summary = f"Verified stable ({active_config.stability_seconds}s window complete)"
                ver_pct = 100
            elif inc.state == State.VERIFYING:
                ver_summary = f"Verifying stability ({active_config.stability_seconds}s window in progress)"
                ver_pct = 50
            else:
                ver_summary = f"Pending execution ({active_config.stability_seconds}s stability window configured)"
                ver_pct = 0

            incidents_out.append({
                "id": inc.id,
                "state": inc.state.value if isinstance(inc.state, State) else str(inc.state),
                "services": inc.services,
                "root_candidates": inc.root_candidates,
                "downstream": inc.downstream,
                "flap_count": inc.flap_count,
                "opened_at": inc.opened_at.isoformat(),
                "root_cause_summary": str(top_h["root_cause"])
                if top_h
                else f"root candidate: {', '.join(inc.root_candidates)}",
                "proposed_action": fix_text,
                "action_risk": act_risk,
                "result_note": result_note,
                "dry_run_note": dry_note,
                "hypotheses": hyps_sorted,
                "events": [
                    {
                        "id": e.id,
                        "timestamp": e.timestamp.isoformat(),
                        "service": e.service,
                        "kind": e.kind.value,
                        "source": e.source,
                        "evidence": e.evidence,
                    }
                    for e in evs
                ],
                "live_target": {
                    "target": target_name or (inc.root_candidates[0] if inc.root_candidates else ""),
                    "state": "healthy" if inc.state == State.RESOLVED else "degraded",
                    "revision": f"rev-{inc.id[:8]}",
                },
                "policy_check": policy_check,
                "verification_summary": ver_summary,
                "verification_progress_pct": ver_pct,
                "postmortem": pm,
            })

        # Approvals queue with expiry countdown and evidence summary
        pending_rows = active_store.connection.execute(
            "SELECT digest, proposal, created_at FROM pending_approvals ORDER BY created_at DESC"
        ).fetchall()
        approvals_out = []
        for digest, prop_json, created_at_str in pending_rows:
            try:
                prop = Proposal.model_validate_json(prop_json)
            except ValidationError:
                continue
            if active_safety.approved(prop):
                continue
            created_dt = datetime.fromisoformat(created_at_str)
            expires_dt = created_dt + timedelta(seconds=300)
            if expires_dt <= now:
                continue
            inc_evs = active_store.incident_events(prop.incident_id)
            ev_summary = (
                inc_evs[-1].evidence
                if inc_evs and inc_evs[-1].evidence
                else f"Incident {prop.incident_id} awaiting approval"
            )
            approvals_out.append({
                "proposal_id": str(digest),
                "incident_id": prop.incident_id,
                "action": prop.name,
                "target": str(prop.params.get("target", "")),
                "expected_revision": prop.expected_revision,
                "confidence": prop.confidence,
                "created_at": created_at_str,
                "expires_at": expires_dt.isoformat(),
                "evidence_summary": ev_summary,
            })

        # Active cooldowns
        cooldown_sec = config.safety.cooldown_seconds
        cd_cutoff = (now - timedelta(seconds=cooldown_sec)).isoformat()
        cd_rows = active_store.connection.execute(
            "SELECT name, target, MAX(started_at) FROM actions WHERE started_at > ? GROUP BY name, target",
            (cd_cutoff,),
        ).fetchall()
        cooldowns_out = []
        for act_n, tgt_n, started_str in cd_rows:
            started_dt = datetime.fromisoformat(started_str)
            rem_sec = max(0, int((started_dt + timedelta(seconds=cooldown_sec) - now).total_seconds()))
            if rem_sec > 0:
                cooldowns_out.append({
                    "action": act_n,
                    "target": tgt_n,
                    "remaining_seconds": rem_sec,
                    "remaining_minutes": max(1, math.ceil(rem_sec / 60)),
                })

        # Interrupted / pending actions
        interrupted_rows = active_store.connection.execute(
            "SELECT id, incident_id, name, target, started_at, status FROM actions WHERE status IN ('reserved','executing','verifying') ORDER BY started_at DESC"
        ).fetchall()
        interrupted_out = [
            {
                "id": r[0],
                "incident_id": r[1],
                "name": r[2],
                "target": r[3],
                "started_at": r[4],
                "status": r[5],
            }
            for r in interrupted_rows
        ]

        # Kill switch history
        ks_rows = active_store.connection.execute(
            "SELECT timestamp, subject, detail FROM audit_log WHERE rule='kill_switch' AND subject!='policy' ORDER BY id DESC LIMIT 20"
        ).fetchall()
        ks_history = [
            {
                "timestamp": r[0],
                "actor": r[1],
                "enabled": str(r[2]).lower() in ("true", "1", "on"),
            }
            for r in ks_rows
        ]

        # Unified activity & audit log
        audit_rows = active_store.connection.execute(
            "SELECT timestamp, subject, rule, detail FROM audit_log ORDER BY id DESC LIMIT 80"
        ).fetchall()
        activity_out = []
        for ts_str, subj, rule, detail in audit_rows:
            res_kind = "control"
            if rule in ("authorized", "verified_success", "human_approval"):
                res_kind = "success"
            elif rule in (
                "kill_switch",
                "circuit_breaker",
                "dry_run",
                "cooldown",
                "hourly_limit",
                "critical_approval_required",
                "approval_required",
                "action_not_enabled_approval_required",
                "low_confidence",
                "flapping_incident",
                "invalid_parameters",
                "unknown_action",
                "forbidden_action",
            ) and subj == "policy":
                res_kind = "refused"
            elif rule == "action_failure":
                res_kind = "failed"

            rem_cd = cooldowns_out[0]["remaining_seconds"] if cooldowns_out and rule == "cooldown" else None
            plain = explain_rule_plainly(rule, detail, rem_cd)
            # Infer service / action when available
            inferred_action = ""
            for act_candidate in registry.actions:
                if act_candidate in detail:
                    inferred_action = act_candidate
                    break
            inferred_service = ""
            for svc_obj in active_config.services:
                if svc_obj.name in detail or svc_obj.name == subj:
                    inferred_service = svc_obj.name
                    break

            activity_out.append({
                "timestamp": ts_str,
                "subject": subj,
                "service": inferred_service or subj,
                "action": inferred_action,
                "rule": rule,
                "result": res_kind,
                "detail": detail,
                "plain_explanation": plain,
            })

        # Recent 5 actions summary
        act_table_rows = active_store.connection.execute(
            "SELECT id, incident_id, name, target, started_at, status FROM actions ORDER BY started_at DESC LIMIT 5"
        ).fetchall()
        recent_actions_out = [
            {
                "id": r[0],
                "incident_id": r[1],
                "action": r[2],
                "target": r[3],
                "timestamp": r[4],
                "result": r[5],
                "plain_result": explain_rule_plainly(
                    "verified_success" if r[5] == "success" else r[5], r[3]
                ),
            }
            for r in act_table_rows
        ]
        # Include recent policy refusals in recent_actions_out if fewer than 5
        for item in activity_out:
            if len(recent_actions_out) >= 5:
                break
            if item["result"] == "refused":
                recent_actions_out.append({
                    "id": "policy-refusal",
                    "incident_id": "",
                    "action": item["action"] or "policy_gate",
                    "target": item["service"],
                    "timestamp": item["timestamp"],
                    "result": "refused",
                    "plain_result": item["plain_explanation"],
                })

        # Resolution breakdown strip (rules / retrieval / local LLM / cloud / human)
        outcomes = active_store.verified_outcomes(only_stable=True)
        breakdown = {"rules": 0, "retrieval": 0, "local_llm": 0, "cloud": 0, "human": 0}
        for o in outcomes:
            pay = o.get("payload") or {}
            tier = str(pay.get("tier") or "D2_RUNBOOK") if isinstance(pay, dict) else "D2_RUNBOOK"
            if "D1" in tier or "MEMORY" in tier:
                breakdown["retrieval"] += 1
            elif "D3" in tier or "LOCAL" in tier:
                breakdown["local_llm"] += 1
            elif "D4" in tier or "CLOUD" in tier:
                breakdown["cloud"] += 1
            elif "HUMAN" in tier:
                breakdown["human"] += 1
            else:
                breakdown["rules"] += 1

        # Doctor report (avoid network probe on every 4s poll by using probe_ollama=False)
        doc_report = build_doctor_report(active_config, probe_ollama=False)

        # First-run guide steps derived from real state
        has_services = len(active_config.services) > 0
        has_critical_or_deps = any(s.critical or s.depends_on for s in active_config.services)
        doctor_clean = doc_report["attention_count"] == 0 and has_services
        has_observed = len(all_incidents) > 0 or len(active_store.events()) > 0
        has_enabled_one = len(active_config.safety.enabled_actions) > 0
        is_live = not active_config.dry_run and has_enabled_one

        guide_steps = [
            {
                "order": 1,
                "title": "Initialize configuration (selfheal init)",
                "detail": f"{len(active_config.services)} service(s) configured in inventory",
                "command": "selfheal init",
                "done": has_services,
            },
            {
                "order": 2,
                "title": "Review services, CRITICAL flags, and dependency map",
                "detail": "Mark stateful/database targets critical: true and wire depends_on",
                "command": "Review config.yaml",
                "done": has_critical_or_deps,
            },
            {
                "order": 3,
                "title": "Verify host readiness (selfheal doctor)",
                "detail": f"{doc_report['attention_count']} component(s) needing attention",
                "command": "selfheal doctor",
                "done": doctor_clean,
            },
            {
                "order": 4,
                "title": "Observe in DRY-RUN mode (Days 1–7)",
                "detail": f"{len(all_incidents)} incident(s) correlated in SQLite store",
                "command": "selfheal run",
                "done": has_observed,
            },
            {
                "order": 5,
                "title": "Enable one safe action (Week 2)",
                "detail": (
                    f"Enabled: {', '.join(active_config.safety.enabled_actions)}"
                    if has_enabled_one
                    else "safety.enabled_actions is currently []"
                ),
                "command": "selfheal enable-action restart_container",
                "done": has_enabled_one,
            },
            {
                "order": 6,
                "title": "Go live with safety gates active",
                "detail": "dry_run is False" if not active_config.dry_run else "Currently in dry_run: true",
                "command": "selfheal dry-run false",
                "done": is_live,
            },
        ]
        next_guide = next((s["command"] for s in guide_steps if not s["done"]), "All onboarding steps complete.")

        hourly_used = active_safety.recent_count()
        if active_store is not db_store:
            active_store.close()
        return {
            "timestamp": now.isoformat(),
            "demo_mode": demo_mode,
            "mode": mode_summary,
            "services": services_out,
            "maintenance_windows": maint_windows,
            "incidents": incidents_out,
            "approvals": approvals_out,
            "recent_actions": recent_actions_out,
            "resolution_breakdown": breakdown,
            "activity": activity_out,
            "safety": {
                "killed": killed,
                "circuit_open": circuit_open,
                "consecutive_failures": consecutive_failures,
                "circuit_breaker_failures": active_config.safety.failure_limit,
                "enabled_actions": list(active_config.safety.enabled_actions),
                "hourly_used": hourly_used,
                "max_auto_per_hour": active_config.safety.max_auto_per_hour,
                "minimum_confidence": active_config.safety.minimum_confidence,
                "cooldowns": cooldowns_out,
                "interrupted_actions": interrupted_out,
                "kill_switch_history": ks_history,
            },
            "doctor": doc_report,
            "first_run": {
                "steps": guide_steps,
                "next_step": next_guide,
            },
        }

    @app.get("/api/health")
    def get_health() -> dict[str, Any]:
        """System health and safety state overview."""
        is_breaker_open = safety_state.circuit_open()
        killed = safety_state.killed()
        failures_row = db_store.connection.execute(
            "SELECT failures FROM safety_control WHERE id=1"
        ).fetchone()
        consecutive_failures = failures_row[0] if failures_row else 0
        mode = compute_mode_summary(
            config, killed=killed, circuit_open=is_breaker_open, store=db_store
        )
        return {
            "status": "halted" if (killed or is_breaker_open) else "healthy",
            "mode_banner": mode["banner_text"],
            "dry_run": config.dry_run,
            "killed": killed,
            "breaker_open": is_breaker_open,
            "consecutive_failures": consecutive_failures,
            "active_services": [s.name for s in config.services],
            "timestamp": utcnow().isoformat(),
        }

    @app.get("/api/incidents")
    def get_incidents() -> dict[str, Any]:
        """List persisted incidents across lifecycles."""
        incidents = db_store.incidents()
        return {
            "incidents": [
                {
                    "id": inc.id,
                    "state": inc.state.value if isinstance(inc.state, State) else str(inc.state),
                    "services": inc.services,
                    "root_candidates": inc.root_candidates,
                    "downstream": inc.downstream,
                    "flap_count": inc.flap_count,
                    "opened_at": inc.opened_at.isoformat()
                    if hasattr(inc.opened_at, "isoformat")
                    else str(inc.opened_at),
                }
                for inc in incidents
            ]
        }

    @app.get("/api/approvals")
    def get_approvals() -> dict[str, Any]:
        """List staged requests without exposing a token or inventing approvals."""
        return {
            "approvals": [
                {
                    "proposal_id": digest,
                    "action": proposal.name,
                    "target": str(proposal.params.get("target", "")),
                    "incident_id": proposal.incident_id,
                    "expected_revision": proposal.expected_revision,
                    "confidence": proposal.confidence,
                }
                for digest, proposal in safety_state.pending()
                if not safety_state.approved(proposal)
            ]
        }

    @app.post("/api/approve")
    def post_approve(req: ApprovalRequest, request: Request) -> dict[str, Any]:
        """Approve only a current staged proposal with a live policy recheck."""
        _verify_csrf_and_origin(request)
        proposal = safety_state.pending_by_digest(req.proposal_id)
        if proposal is None:
            raise HTTPException(status_code=404, detail="No staged proposal")
        incident = next((i for i in db_store.incidents() if i.id == proposal.incident_id), None)
        if incident is None or incident.state not in (
            State.OPEN,
            State.INVESTIGATING,
            State.ESCALATED,
        ):
            raise HTTPException(status_code=409, detail="Incident is no longer awaiting review")
        decision = policy.evaluate(proposal, DiagnosisContext(incident_id=proposal.incident_id))
        if decision.rule not in (
            "approval_required",
            "critical_approval_required",
            "action_not_enabled_approval_required",
        ):
            raise HTTPException(
                status_code=409, detail=f"Proposal no longer approvable: {decision.rule}"
            )
        safety_state.approve(proposal, "dashboard")
        with safety_state.transaction():
            db_store.connection.execute(
                "DELETE FROM pending_approvals WHERE digest=?", (req.proposal_id,)
            )
            db_store.audit("dashboard", "human_approval", req.proposal_id)
        return {
            "status": "approved",
            "proposal_id": req.proposal_id,
            "actor": "dashboard",
            "timestamp": utcnow().isoformat(),
        }

    @app.post("/api/reject")
    def post_reject(req: ApprovalRequest, request: Request) -> dict[str, Any]:
        """Reject and remove a staged proposal, recording actor 'dashboard' in audit_log."""
        _verify_csrf_and_origin(request)
        proposal = safety_state.pending_by_digest(req.proposal_id)
        if proposal is None:
            raise HTTPException(status_code=404, detail="No staged proposal")
        with safety_state.transaction():
            db_store.connection.execute(
                "DELETE FROM pending_approvals WHERE digest=?", (req.proposal_id,)
            )
            db_store.audit(
                "dashboard",
                "approval_rejected",
                f"{proposal.incident_id}:{req.proposal_id}",
            )
        return {
            "status": "rejected",
            "proposal_id": req.proposal_id,
            "actor": "dashboard",
            "timestamp": utcnow().isoformat(),
        }

    @app.post("/api/kill-switch")
    def post_kill_switch(req: KillSwitchRequest, request: Request) -> dict[str, Any]:
        """Engage or disengage the global kill switch through SafetyState, recording actor 'dashboard'."""
        _verify_csrf_and_origin(request)
        safety_state.kill_switch(req.enabled, "dashboard")
        return {
            "status": "engaged" if req.enabled else "disengaged",
            "killed": safety_state.killed(),
            "actor": "dashboard",
            "timestamp": utcnow().isoformat(),
        }

    @app.post("/api/dry-run")
    def post_dry_run(req: DryRunRequest, request: Request) -> dict[str, Any]:
        """Toggle dry-run mode through the same configuration and audit path as the CLI."""
        _verify_csrf_and_origin(request)
        config.dry_run = req.enabled
        policy.dry_run = req.enabled
        if config_path is not None and config_path.exists():
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            data["dry_run"] = req.enabled
            config_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        db_store.audit("dashboard", "dry_run_toggle", str(req.enabled))
        return {
            "status": "updated",
            "dry_run": config.dry_run,
            "actor": "dashboard",
            "timestamp": utcnow().isoformat(),
        }

    @app.get("/api/history")
    def get_history() -> dict[str, Any]:
        """Retrieve verified historical outcomes."""
        outcomes = db_store.verified_outcomes(only_stable=False)
        return {"outcomes": outcomes}

    @app.get("/api/tiers")
    def get_tiers() -> dict[str, Any]:
        """Return operational status of diagnosis tiers D1-D5."""
        cloud_ready = bool(
            config.cloud_enabled
            and config.cloud_base_url
            and config.cloud_model
            and config.cloud_max_calls_per_month
            and config.cloud_max_spend_usd
            and config.cloud_estimated_max_cost_per_call_usd
            and os.environ.get("SLIME_CLOUD_API_KEY")
        )
        laya_ready = bool(
            config.laya_enabled
            and importlib.util.find_spec("laya")
            and LayaClassifier(config, db_store).evaluation() is not None
        )
        return {
            "tiers": [
                {"name": "D1 Memory", "type": "BM25 Verified Outcomes", "status": "active"},
                {"name": "D2 Runbooks", "type": "Declarative Policy Rules", "status": "active"},
                {
                    "name": "D3 Local LLM",
                    "type": f"Ollama ({config.ollama_model})",
                    "status": "active",
                },
                {
                    "name": "D4 Cloud LLM",
                    "type": "Opt-in Cloud LLM",
                    "status": "configured" if cloud_ready else "inactive",
                },
                {
                    "name": "D5 Laya",
                    "type": "Opt-in Neural/Linear Classifier",
                    "status": "eligible" if laya_ready else "inactive",
                },
            ]
        }

    @app.get("/api/audit")
    def get_audit(limit: int = 50) -> dict[str, Any]:
        """Retrieve recent durable audit entries."""
        rows = db_store.connection.execute(
            "SELECT timestamp, subject, rule, detail FROM audit_log ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return {
            "audit": [
                {
                    "timestamp": r[0],
                    "subject": r[1],
                    "rule": r[2],
                    "detail": r[3],
                }
                for r in rows
            ]
        }

    return app


def run_dashboard(
    config: Config,
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    demo: bool = False,
    config_path: Path | None = None,
) -> None:
    """Launch the localhost-only FastAPI dashboard."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"Security violation: Dashboard is strictly localhost-only. Host '{host}' is forbidden."
        )

    token = secrets.token_urlsafe(32)
    print(f"Dashboard session token (required on every request): {token}")
    print(f"Dashboard URL: http://{host}:{port}/?token={token}")

    if demo:
        from selfheal.interface.dashboard_demo import seed_demo_database

        with tempfile.TemporaryDirectory(prefix="slime_demo_") as tmp_dir:
            demo_ws = Path(tmp_dir)
            demo_cfg, demo_store = seed_demo_database(demo_ws, preset="default")
            try:
                app = create_dashboard_app(
                    demo_cfg,
                    store=demo_store,
                    approval_token=token,
                    session_token=token,
                    demo_mode=True,
                    demo_workspace=demo_ws,
                )
                uvicorn.run(app, host=host, port=port, log_level="info")
            finally:
                demo_store.close()
        return

    app = create_dashboard_app(
        config,
        approval_token=token,
        session_token=token,
        config_path=config_path,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")
