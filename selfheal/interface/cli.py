"""Environment-aware setup, diagnosis, and CLI commands for Slime."""

import getpass
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from selfheal.config import Config, load_config
from selfheal.interface.dashboard import (
    build_doctor_report,
    compute_mode_summary,
    evaluate_ordered_policy_gates,
    format_incident_execution_note,
)
from selfheal.models import State
from selfheal.remediation.registry import default_registry
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import Proposal
from selfheal.safety.state import SafetyState, proposal_digest
from selfheal.storage.store import Store

app = typer.Typer(help="Slime: local-first, safety-first DevOps incident agent.")
console = Console()


def _use_plain_output() -> bool:
    """Return True when NO_COLOR is set or stdout is not an interactive TTY."""
    return bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()


def _out(text: str, *, style: str | None = None) -> None:
    """Print one line respecting NO_COLOR and non-TTY streams without narrow table wrapping."""
    if _use_plain_output() or not style:
        typer.echo(text)
    else:
        console.print(text, style=style, markup=False, soft_wrap=True)



def get_current_actor(actor_override: str | None = None) -> str:
    """Resolve trusted local actor identity."""
    if actor_override and actor_override.strip():
        return actor_override.strip()
    try:
        user = getpass.getuser()
        if user:
            return user
    except Exception:  # noqa: BLE001, S110
        pass
    return "operator"


@app.command()
def init(
    config: Path = Path("config.yaml"),
    scan_dir: Annotated[Path | None, typer.Option("--scan-dir", help="Optional directory to scan for logs and nginx.conf")] = None,
) -> None:
    """Scan the machine and write explicit, dry-run configuration without overwriting."""
    if config.exists():
        console.print("Configuration exists; refusing to overwrite.", markup=False)
        raise typer.Exit(1)
    from selfheal.interface.discovery import scan_host

    settings, summary = scan_host(scan_dir)
    config.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    console.print(
        f"Created {config.absolute()} on {platform.system()}; dry-run enabled.", markup=False
    )
    console.print(
        f"Scanned host: {len(summary.log_files)} log file(s), "
        f"{len(summary.systemd_units)} systemd unit(s), "
        f"{len(summary.docker_containers)} Docker container(s), "
        f"{len(summary.listening_ports)} listening port(s), "
        f"{len(summary.nginx_upstreams)} nginx upstream(s).",
        markup=False,
    )
    console.print(
        "Review services to watch, CRITICAL flags, dependency map, and maintenance windows."
    )
    console.print(
        f"journalctl: {'available' if shutil.which('journalctl') else 'unavailable on this host'}"
    )


@app.command()
def doctor(config: Path = Path("config.yaml")) -> None:
    """Report grouped collectors, diagnosis tiers, safety gates, host capabilities, and next step."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError):
        _out("Invalid or missing configuration. Run selfheal init or correct config.yaml.")
        raise typer.Exit(1) from None

    try:
        with httpx.Client(timeout=1, trust_env=False) as client:
            response = client.get("http://127.0.0.1:11434/api/tags")
            response.raise_for_status()
        ollama_status = "reachable"
    except httpx.HTTPError:
        ollama_status = "unavailable (optional)"

    report = build_doctor_report(settings, probe_ollama=False)
    for item in report["groups"]["Diagnosis"]:
        if item["component"] == "Ollama / D3":
            item["status"] = ollama_status

    _out("Slime System Doctor")
    _out("=" * 78)
    for group_name in ("Collectors", "Diagnosis", "Safety", "Platform"):
        _out(f"\n[{group_name}]")
        for item in report["groups"][group_name]:
            comp = str(item["component"])
            st = str(item["status"])
            detail = str(item["detail"])
            if item["needs_attention"]:
                _out(f"  [!] {comp:<22} {st:<18} {detail}", style="bold yellow")
                if item.get("fix"):
                    _out(f"      Fix: {item['fix']}", style="yellow")
            else:
                _out(f"  [OK] {comp:<21} {st:<18} {detail}")

    _out(f"\n[Host Capability ({report['host_os']})]")
    for cap in report["capabilities"]:
        c_name = str(cap["capability"])
        c_stat = str(cap["status"])
        c_det = str(cap["detail"])
        _out(f"  - {c_name}: {c_stat} ({c_det})")

    _out(f"\nNext step: {report['next_step']}", style="bold" if not _use_plain_output() else None)


@app.command()
def run(
    config: Path = Path("config.yaml"),
    dry_run: Annotated[bool | None, typer.Option("--dry-run/--no-dry-run", help="Override dry-run mode")] = None,
    once: Annotated[bool, typer.Option("--once", help="Run one cycle and exit")] = False,
) -> None:
    """Run polling, correlation, diagnosis, policy, execution and postmortem."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    if dry_run is not None:
        settings.dry_run = dry_run

    console.print(
        Panel(
            f"[bold blue]Slime Incident Runtime[/bold blue]\n"
            f"Mode: {'[yellow]DRY-RUN[/yellow]' if settings.dry_run else '[red]ACTIVE MUTATION[/red]'}\n"
            f"Database: {settings.database}\n"
            f"Min confidence: {settings.safety.minimum_confidence}",
            title="Runtime Configuration",
        )
    )

    coordinator = Coordinator(settings)
    try:
        while True:
            results = coordinator.step()
            if not results and once:
                console.print("No active incidents requiring remediation.")
            for incident, diagnosis, proposals, exec_res in results:
                console.print(f"\n[bold]Incident {incident.id}[/bold] (State: `{incident.state.value}`)")
                console.print(f"  Diagnosis Tier: {diagnosis.deciding_tier} (Status: {diagnosis.status})")
                if diagnosis.selected:
                    console.print(f"  Root Cause Hypothesis: {diagnosis.selected.hypothesis}")
                    console.print(f"  Confidence: {diagnosis.selected.confidence:.2f}")
                    if diagnosis.selected.rationale:
                        console.print(f"  Rationale: {diagnosis.selected.rationale}")

                if proposals:
                    top = proposals[0]
                    console.print(f"  Proposed Action: [cyan]{top.proposal.name}[/cyan] (Score: {top.score:.2f})")
                    console.print(f"  Target: {top.proposal.params.get('target', 'unknown')}")
                else:
                    console.print("  [yellow]No viable repair proposals generated.[/yellow]")

                if exec_res:
                    console.print(f"  Execution Status: [bold]{exec_res.status}[/bold]")
                    console.print(f"  Policy Rule: {exec_res.rule}")
                    if exec_res.decision.needs_human:
                        console.print("  [yellow]Approval Required:[/yellow] Use `selfheal approve` to authorize.")
                    if exec_res.verification:
                        v = exec_res.verification
                        console.print(
                            f"  Verification: {'[green]Stable[/green]' if v.stable else '[red]Unstable[/red]'} ({v.reason})"
                        )
            if once:
                break
            time.sleep(settings.poll_seconds)
    except KeyboardInterrupt:
        console.print("Monitoring stopped by operator.")
    finally:
        coordinator.close()


@app.command()
def status(
    config: Path = Path("config.yaml"),
    json_output: Annotated[bool, typer.Option("--json", help="Output status in JSON format")] = False,
) -> None:
    """Display system health, mode banner, open incidents, active components, and safety controls."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        _out(f"Error loading config: {e}")
        raise typer.Exit(1) from None

    store = Store(settings.database)
    state = SafetyState(store)
    try:
        killed = state.killed()
        circuit_open = state.circuit_open()
        recent_count = state.recent_count()
        all_incidents = store.incidents()
        open_incidents = [
            i for i in all_incidents if i.state not in {State.RESOLVED, State.ESCALATED}
        ]
        escalated_incidents = [i for i in all_incidents if i.state == State.ESCALATED]
        pending_approvals = [
            (d, p) for d, p in state.pending() if not state.approved(p)
        ]
        health_str = (
            "HALTED"
            if (killed or circuit_open)
            else ("DEGRADED" if (open_incidents or escalated_incidents) else "HEALTHY")
        )
        mode_info = compute_mode_summary(
            settings, killed=killed, circuit_open=circuit_open, store=store
        )
        active_components = ["D1_MEMORY", "D2_RUNBOOK"]
        if settings.metrics_enabled:
            active_components.insert(0, "psutil_metrics")
        if settings.services:
            active_components.append(f"{len(settings.services)}_services")

        pending_actions = store.connection.execute(
            "SELECT id, incident_id, name, target, started_at, status FROM actions WHERE status IN ('reserved','executing','verifying') ORDER BY started_at"
        ).fetchall()

        if json_output:
            payload = {
                "system_health": health_str,
                "mode": mode_info["banner_text"],
                "mode_state": mode_info["state"],
                "dry_run": settings.dry_run,
                "learning_period": settings.learning_period,
                "learning_day": mode_info["learning_day"] if settings.learning_period else None,
                "open_incidents": len(open_incidents),
                "escalated_incidents": len(escalated_incidents),
                "total_incidents": len(all_incidents),
                "pending_approvals": len(pending_approvals),
                "active_components": active_components,
                "kill_switch": "ACTIVE" if killed else "INACTIVE",
                "circuit_breaker": "OPEN" if circuit_open else "CLOSED",
                "hourly_auto_count": recent_count,
                "max_auto_per_hour": settings.safety.max_auto_per_hour,
                "enabled_actions": list(settings.safety.enabled_actions),
                "pending_actions": [
                    {
                        "id": r[0],
                        "incident_id": r[1],
                        "action": r[2],
                        "target": r[3],
                        "started_at": r[4],
                        "status": r[5],
                    }
                    for r in pending_actions
                ],
            }
            typer.echo(json.dumps(payload, indent=2))
            return

        _out("Slime System Status")
        _out("=" * 78)
        _out(f"Mode            : {mode_info['banner_text']}")
        _out(
            f"System health   : {health_str} "
            f"(open: {len(open_incidents)}, escalated: {len(escalated_incidents)}, total: {len(all_incidents)})"
        )
        if settings.learning_period:
            _out(f"Learning period : Observing: day {mode_info['learning_day']} of 7 (baseline building)")
        _out(f"Pending review  : {len(pending_approvals)} approval(s) queued")
        _out(f"Active pipeline : {', '.join(active_components)}")
        _out(f"Kill switch     : {'ACTIVE (all mutations halted)' if killed else 'INACTIVE'}")
        _out(f"Circuit breaker : {'OPEN (requires reconcile + reset-circuit)' if circuit_open else 'CLOSED'}")
        _out(f"Hourly budget   : {recent_count} / {settings.safety.max_auto_per_hour} automatic reservations used")
        _out(
            f"Enabled actions : {', '.join(settings.safety.enabled_actions) if settings.safety.enabled_actions else 'none (default)'}"
        )
        if pending_actions:
            _out("\nPending / Interrupted Actions (require `selfheal reconcile <action_id>`):")
            for r in pending_actions:
                _out(f"  - {r[0]} | incident={r[1]} | {r[2]} on {r[3]} | status={r[5]}")
    finally:
        store.close()


def _truncate_cell(value: str, width: int) -> str:
    """Fit a value into fixed width without multi-line wrapping."""
    clean_val = " ".join(value.split())
    if len(clean_val) <= width:
        return f"{clean_val:<{width}}"
    if width <= 1:
        return clean_val[:width]
    return f"{clean_val[: width - 1]}~"


@app.command()
def incidents(
    incident_id: Annotated[str | None, typer.Argument(help="Optional incident ID or prefix for detail view")] = None,
    config: Path = Path("config.yaml"),
    limit: Annotated[int, typer.Option("--limit", help="Max incidents to list")] = 10,
    show_postmortem: Annotated[str | None, typer.Option("--postmortem", help="Incident ID to display postmortem for")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Output incidents in JSON format")] = False,
) -> None:
    """List incidents in an 80-column one-line format, or inspect a single incident in detail."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        _out(f"Error loading config: {e}")
        raise typer.Exit(1) from None

    store = Store(settings.database)
    safety_state = SafetyState(store)
    registry = default_registry()
    try:
        if show_postmortem:
            pm = store.postmortem(show_postmortem)
            if not pm:
                _out(f"No postmortem found for incident {show_postmortem}.")
            else:
                _out(str(pm["markdown"]))
            return

        all_incidents = store.incidents()
        if not all_incidents:
            if json_output:
                typer.echo(json.dumps({"incidents": []}, indent=2))
            else:
                _out("No incidents recorded. Run `selfheal run` to observe services in dry-run.")
            return

        # Detail view when incident_id (full or prefix) is supplied
        if incident_id is not None:
            matched = [
                inc for inc in all_incidents if inc.id == incident_id or inc.id.startswith(incident_id)
            ]
            if not matched:
                _out(f"Incident '{incident_id}' not found.")
                raise typer.Exit(1)
            inc = matched[-1]
            hyps = sorted(
                store.hypotheses(inc.id),
                key=lambda h: float(h.get("confidence", 0.0)),  # type: ignore[arg-type]
                reverse=True,
            )
            top_h: dict[str, Any] | None = hyps[0] if hyps else None
            evs = store.incident_events(inc.id)
            pm = store.postmortem(inc.id)
            result_note, dry_note, fix_text = format_incident_execution_note(
                inc, top_h, settings, store, registry
            )
            policy_check = evaluate_ordered_policy_gates(
                inc, top_h, settings, safety_state, registry, None
            )

            if json_output:
                detail_payload = {
                    "id": inc.id,
                    "state": inc.state.value,
                    "opened_at": inc.opened_at.isoformat(),
                    "services": inc.services,
                    "root_candidates": inc.root_candidates,
                    "downstream": inc.downstream,
                    "flap_count": inc.flap_count,
                    "proposed_fix": fix_text,
                    "result": result_note,
                    "dry_run_note": dry_note,
                    "hypotheses": hyps,
                    "events": [e.model_dump(mode="json") for e in evs],
                    "policy_check": policy_check,
                    "postmortem": pm,
                }
                typer.echo(json.dumps(detail_payload, indent=2))
                return

            _out(f"Incident Detail: {inc.id}")
            _out("=" * 78)
            _out(f"State           : {inc.state.value}")
            _out(f"Opened at       : {inc.opened_at.isoformat()}")
            _out(f"Services        : {', '.join(inc.services)}")
            _out(f"Root candidates : {', '.join(inc.root_candidates)}")
            _out(f"Downstream      : {', '.join(inc.downstream) if inc.downstream else 'none'}")
            _out(f"Flap count      : {inc.flap_count}")
            _out(f"Proposed action : {fix_text}")
            _out(f"Outcome / Note  : {result_note}")
            _out("\nHypotheses:")
            if not hyps:
                _out("  (none)")
            for idx, h in enumerate(hyps, start=1):
                _out(
                    f"  {idx}. [{h['tier']}] conf={float(h['confidence']):.2f} | "  # type: ignore[arg-type]
                    f"{h['root_cause']} -> {h.get('action_name') or 'suggest-only'}"
                )
            _out("\nPolicy Check (in gate order):")
            for gate in policy_check["gates"]:
                tag = (
                    "PASS"
                    if gate["status"] == "passed"
                    else ("STOP" if gate["status"] == "failed" else "----")
                )
                _out(f"  [{tag}] {gate['order']:>2}. {gate['name']}: {gate['detail']}")
            _out("\nTimeline Events:")
            for ev in evs:
                _out(f"  - {ev.timestamp.isoformat()} [{ev.service}/{ev.kind.value}] {ev.evidence}")
            if pm:
                _out(f"\nPostmortem: available (`selfheal incidents --postmortem {inc.id}`)")
            return

        # List view: strictly <= 80 columns, one line per incident, zero multi-line cell wrapping
        rows_json = []
        header = (
            f"{'ID':<8} {'STATE':<9} {'SERVICES':<8} "
            f"{'ROOT CAUSE':<10} {'ACTION':<13} {'RESULT'}"
        )
        lines = [header, "-" * 78]

        for inc in all_incidents[-limit:]:
            hyps = store.hypotheses(inc.id)
            top_h = (
                max(hyps, key=lambda h: float(h.get("confidence", 0.0)))  # type: ignore[arg-type]
                if hyps
                else None
            )
            result_note, dry_note, fix_text = format_incident_execution_note(
                inc, top_h, settings, store, registry
            )
            root_cause_str = (
                str(top_h["root_cause"])
                if top_h
                else (",".join(inc.root_candidates) or "unknown")
            )
            act_short = (
                str(top_h["action_name"])
                if (top_h and top_h.get("action_name"))
                else "suggest-only"
            )
            rows_json.append({
                "id": inc.id,
                "id_prefix": inc.id[:8],
                "state": inc.state.value,
                "services": inc.services,
                "root_cause": root_cause_str,
                "action": act_short,
                "proposed_fix": fix_text,
                "result": result_note,
                "dry_run_note": dry_note,
            })
            list_result = result_note.removeprefix(f"{act_short}: ")
            line = (
                f"{_truncate_cell(inc.id[:8], 8)} "
                f"{_truncate_cell(inc.state.value, 9)} "
                f"{_truncate_cell(','.join(inc.services), 8)} "
                f"{_truncate_cell(root_cause_str, 10)} "
                f"{_truncate_cell(act_short, 13)} "
                f"{list_result[:26]}"
            )
            lines.append(line)

        if json_output:
            typer.echo(json.dumps({"incidents": rows_json}, indent=2))
            return

        for ln in lines:
            _out(ln)
    finally:
        store.close()


@app.command()
def approve(
    incident_id: str,
    action: Annotated[str | None, typer.Argument(help="Action name (optional if staged)")] = None,
    target: Annotated[str | None, typer.Argument(help="Target alias (optional if staged)")] = None,
    revision: Annotated[str | None, typer.Argument(help="Revision (optional if staged)")] = None,
    config: Path = Path("config.yaml"),
    actor: Annotated[str | None, typer.Option("--actor", help="Operator username/identity")] = None,
    lifetime: Annotated[int, typer.Option("--lifetime", help="Approval validity in seconds")] = 300,
    confidence: Annotated[float, typer.Option("--confidence", help="Validated confidence")] = 0.95,
) -> None:
    """Record a single-use human approval bound to exact proposal, parameters, and revision."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    trusted_actor = get_current_actor(actor)
    store = Store(settings.database)
    state = SafetyState(store)
    try:
        prop: Proposal | None = None
        if action is None or target is None or revision is None:
            # Resolve from staged pending approvals by exact digest first
            prop = state.pending_by_digest(incident_id)
            if prop is None:
                all_pending = state.pending()
                matching = [
                    (digest_val, candidate)
                    for digest_val, candidate in all_pending
                    if candidate.incident_id == incident_id
                ]
                if len(matching) > 1 or (len(matching) == 1 and len(all_pending) > 1):
                    to_list = matching if len(matching) > 1 else all_pending
                    console.print(
                        "[red]Multiple proposals are staged; refusing ambiguous approval by incident ID. "
                        "Run `selfheal approve <digest>` with the exact digest:[/red]"
                    )
                    for digest_val, candidate in to_list:
                        console.print(
                            f"  digest={digest_val} incident={candidate.incident_id} "
                            f"action={candidate.name} target={candidate.params.get('target')} "
                            f"revision={candidate.expected_revision}",
                            markup=False,
                        )
                    raise typer.Exit(1)
                if len(matching) == 1:
                    prop = matching[0][1]
            if prop is None:
                console.print(
                    f"[red]No staged pending approval found for '{incident_id}'. "
                    "Supply <incident_id> <action> <target> <revision> explicitly.[/red]"
                )
                raise typer.Exit(1)
        else:
            prop = Proposal(
                incident_id=incident_id,
                name=action,
                params={"target": target},
                expected_revision=revision,
                confidence=confidence,
            )
        digest = proposal_digest(prop)
        state.approve(prop, trusted_actor, lifetime_seconds=lifetime)
        console.print(f"[green]Approval granted by '{trusted_actor}'[/green]")
        console.print(f"Proposal Digest: [cyan]{digest}[/cyan]")
        console.print(
            f"Action: {prop.name} on {prop.params.get('target')} (Revision: {prop.expected_revision})"
        )
        console.print(f"Valid for {lifetime} seconds.")
    finally:
        store.close()


@app.command(name="enable-action")
def enable_action(
    actions: Annotated[list[str], typer.Argument(help="Action names to allow for auto-execution")],
    config: Path = Path("config.yaml"),
) -> None:
    """Enable real auto-execution only for specific SAFE actions in config.yaml."""
    if not config.exists():
        console.print(f"Configuration file {config} not found.")
        raise typer.Exit(1)
    reg = default_registry()
    for act in actions:
        try:
            reg.get(act)
        except LookupError:
            console.print(f"Unknown action: {act}", markup=False)
            raise typer.Exit(1) from None
    data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    safety_block = dict(data.get("safety") or {})
    safety_block["enabled_actions"] = list(dict.fromkeys(actions))
    data["safety"] = safety_block
    config.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    console.print(f"Enabled actions in {config.name}: {', '.join(safety_block['enabled_actions'])}")


@app.command(name="dry-run")
def set_dry_run(
    enabled: Annotated[bool, typer.Argument(help="Enable (true/on) or disable (false/off) dry-run; defaults to true")] = True,
    config: Path = Path("config.yaml"),
) -> None:
    """Return to observe-only (dry-run) or update dry-run configuration safely."""
    if not config.exists():
        console.print(f"Configuration file {config} not found.")
        raise typer.Exit(1)

    data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    data["dry_run"] = enabled
    config.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    console.print(f"Updated {config.name}: dry_run = {enabled}")


@app.command(name="kill-switch")
def kill_switch(
    enable: Annotated[bool, typer.Argument(help="on/true to engage kill switch, off/false to disengage")],
    config: Path = Path("config.yaml"),
    actor: Annotated[str | None, typer.Option("--actor", help="Operator username/identity")] = None,
) -> None:
    """Engage or disengage the global mutation kill switch (`selfheal kill-switch on|off`)."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    trusted_actor = get_current_actor(actor)
    store = Store(settings.database)
    state = SafetyState(store)
    try:
        state.kill_switch(enable, trusted_actor)
        if enable:
            console.print(f"[red]Kill switch ENGAGED by '{trusted_actor}'. All mutations halted.[/red]")
        else:
            console.print(f"[green]Kill switch DISENGAGED by '{trusted_actor}'.[/green]")
    finally:
        store.close()


@app.command(name="reset-circuit")
def reset_circuit(
    config: Path = Path("config.yaml"),
    actor: Annotated[str | None, typer.Option("--actor", help="Operator username/identity")] = None,
) -> None:
    """Reset the circuit breaker after consecutive failures."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    trusted_actor = get_current_actor(actor)
    store = Store(settings.database)
    state = SafetyState(store)
    try:
        state.reset_circuit(trusted_actor)
        console.print(f"[green]Circuit breaker RESET by '{trusted_actor}'.[/green]")
    except ValueError as ve:
        console.print(f"[red]Cannot reset circuit:[/red] {ve}")
        raise typer.Exit(1) from None
    finally:
        store.close()


@app.command()
def reconcile(
    action_id: str,
    config: Path = Path("config.yaml"),
    actor: Annotated[str | None, typer.Option("--actor", help="Operator username/identity")] = None,
) -> None:
    """Human acknowledges an uncertain/interrupted action attempt to clear pending state."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    trusted_actor = get_current_actor(actor)
    store = Store(settings.database)
    state = SafetyState(store)
    try:
        state.reconcile_interrupted(action_id, trusted_actor)
        console.print(f"[green]Action {action_id} reconciled as failed by '{trusted_actor}'.[/green]")
        console.print("Circuit breaker is now open. Inspect target manually and run `selfheal reset-circuit`.")
    except ValueError as ve:
        console.print(f"[red]Reconciliation failed:[/red] {ve}")
        raise typer.Exit(1) from None
    finally:
        store.close()


@app.command()
def chaos(
    config: Path = Path("config.yaml"),
    output: Annotated[Path, typer.Option("--output", help="Path to export JSONL ground-truth records")] = Path("chaos_results.jsonl"),
    scratch_dir: Annotated[Path, typer.Option("--scratch", help="Private directory for bounded experiments")] = Path("scratch/chaos"),
    docker_demo: Annotated[bool, typer.Option("--docker-demo", help="Inject only into the labeled slime-demo Compose project")] = False,
) -> None:
    """Run local chaos or explicitly opt in to the disposable Docker demo."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    from selfheal.chaos.harness import ChaosHarness
    from selfheal.chaos.scenarios import adversarial_scenarios, standard_scenarios

    if docker_demo:
        from selfheal.chaos.docker_harness import DEMO_CONTAINERS, DockerDemoHarness, demo_scenarios

        configured = {s.name: s.container_name for s in settings.services}
        if any(configured.get(name) != target for name, target in DEMO_CONTAINERS.items()):
            console.print("Docker demo requires worker/web services with exact slime-demo container names.")
            raise typer.Exit(1)
    coordinator = Coordinator(settings)
    harness = DockerDemoHarness(scratch_dir, coordinator) if docker_demo else ChaosHarness(scratch_dir, coordinator)
    all_scenarios = demo_scenarios() if docker_demo else standard_scenarios() + adversarial_scenarios()
    outcomes = []

    table = Table(title="Chaos Experiments Summary")
    table.add_column("Scenario", style="bold")
    table.add_column("Type")
    table.add_column("Detected")
    table.add_column("Planned Action")
    table.add_column("Policy Rule")
    table.add_column("Safe / Prevented")

    try:
        for sc in all_scenarios:
            out = harness.run_experiment(sc)
            outcomes.append(out)
            safe_text = "[green]YES[/green]" if out.unsafe_action_prevented else "[red]NO[/red]"
            table.add_row(
                sc.name,
                sc.fault_type.value,
                "[green]YES[/green]" if out.detected else "[yellow]NO[/yellow]",
                str(out.planned_action or "None"),
                out.policy_rule,
                safe_text,
            )
        console.print(table)
        harness.export_jsonl(outcomes, output)
        console.print(f"[green]Exported ground truth to {output}[/green]")
    finally:
        coordinator.close()


@app.command()
def bench(
    config: Path = Path("config.yaml"),
    dataset: Annotated[str, typer.Option("--dataset", help="Dataset adapter ('local', 'train-ticket', 'aiops')")] = "local",
    tiers: Annotated[str, typer.Option("--tiers", help="Comma-separated tiers to evaluate")] = "D2_RUNBOOK,COMBINED",
    json_output: Annotated[bool, typer.Option("--json", help="Output results in JSON format")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Optional file path to export JSON results")] = None,
) -> None:
    """Run the 7-case smoke test (or adapter suite) across enabled tiers and report detection, repair, false-incident, and safety metrics."""
    try:
        settings = load_config(config) if config.exists() else Config(database=":memory:")
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    from selfheal.eval.dataset_adapters import (
        AIOpsChallengeAdapter,
        DatasetAdapter,
        LocalCatalogAdapter,
        TrainTicketAdapter,
    )
    from selfheal.eval.runner import BenchmarkRunner

    # Select dataset adapter
    adapter: DatasetAdapter
    if dataset == "train-ticket":
        adapter = TrainTicketAdapter()
    elif dataset == "aiops":
        adapter = AIOpsChallengeAdapter()
    else:
        adapter = LocalCatalogAdapter(include_adversarial=True)

    tier_list = [t.strip() for t in tiers.split(",") if t.strip()]
    runner = BenchmarkRunner(config=settings, adapter=adapter, tiers=tier_list)
    report = runner.run()

    if output:
        output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"[green]Smoke test report exported to {output}[/green]")

    if json_output:
        console.print(report.model_dump_json(indent=2))
        return

    console.print(f"\n[bold]Dataset:[/bold] {report.dataset_name} ({report.dataset_license}) — 7-Case Smoke Test")
    for note in report.adapter_notes:
        console.print(f"[dim]{note}[/dim]")

    table = Table(title="\n7-Case Smoke Test by Tier")
    table.add_column("Tier", style="bold", no_wrap=True)
    table.add_column("Cases", justify="right", no_wrap=True)
    table.add_column("Detect", justify="right", no_wrap=True)
    table.add_column("DiagMatch", justify="right", no_wrap=True)
    table.add_column("Fix", justify="right", no_wrap=True)
    table.add_column("FalseInc", justify="right", no_wrap=True)
    table.add_column("Unsafe", justify="right", no_wrap=True)
    table.add_column("ms", justify="right", no_wrap=True)

    for tier_name, m in report.tiers.items():
        unsafe_styled = f"[green]{m.unsafe_attempt_rate:.1%}[/green]" if m.unsafe_attempts == 0 else f"[red]{m.unsafe_attempt_rate:.1%}[/red]"
        false_inc_text = (
            f"{m.false_incidents}/{m.non_incident_scenarios}"
            if m.non_incident_scenarios
            else "0/0"
        )
        table.add_row(
            tier_name,
            f"{m.total_scenarios}",
            f"{m.detection_rate:.1%}",
            f"{m.diagnosis_match_rate:.1%}",
            f"{m.correct_fix_rate:.1%}" if m.total_scenarios else "N/A",
            false_inc_text,
            unsafe_styled,
            f"{m.mean_latency_ms:.1f}",
        )

    console.print(table)


@app.command()
def eval(
    dataset: Annotated[Path, typer.Option("--dataset", help="Held-out labeled JSONL file")],
    output: Annotated[Path, typer.Option("--output", help="Evaluation report JSON")],
    config: Path = Path("config.yaml"),
) -> None:
    """Compare optional Laya with local memory/runbooks on held-out cases."""
    from selfheal.eval.laya_gate import evaluate_laya

    try:
        settings = load_config(config)
        store = Store(":memory:")
        try:
            report = evaluate_laya(dataset, settings, store)
        finally:
            store.close()
        output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(report.model_dump_json(indent=2), markup=False)
        console.print("Configure laya_eval_report and a required accuracy margin to enable D5.")
    except (OSError, ValueError, ImportError) as exc:
        console.print(f"Laya evaluation unavailable: {type(exc).__name__}: {exc}", markup=False)
        raise typer.Exit(1) from None


@app.command()
def dashboard(
    config: Path = Path("config.yaml"),
    host: Annotated[str, typer.Option("--host", help="Binding host (strictly localhost-only)")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to listen on")] = 8080,
    demo: Annotated[bool, typer.Option("--demo", help="Seed a demo database from the chaos harness and serve read-only")] = False,
) -> None:
    """Launch the optional one-page localhost-only FastAPI dashboard."""
    if host not in ("127.0.0.1", "localhost"):
        console.print(
            f"[red]Security error:[/red] Host '{host}' is forbidden. Dashboard is strictly localhost-only (127.0.0.1)."
        )
        raise typer.Exit(1)

    if demo:
        settings = Config(database=":memory:")
    else:
        try:
            settings = load_config(config)
        except (OSError, ValueError, yaml.YAMLError) as e:
            console.print(f"[red]Error loading config:[/red] {e}")
            raise typer.Exit(1) from None

    try:
        from selfheal.interface.dashboard import run_dashboard

        mode_label = " (READ-ONLY DEMO)" if demo else ""
        console.print(
            f"[green]Starting Slime Dashboard{mode_label} on http://{host}:{port}...[/green]"
        )
        run_dashboard(settings, host=host, port=port, demo=demo, config_path=None if demo else config)
    except ImportError as e:
        console.print(f"[yellow]Dashboard optional dependencies not installed:[/yellow] {e}")
        console.print("Install with: [bold]pip install -e '.[dashboard]'[/bold]")
        raise typer.Exit(1) from None
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Dashboard failed to start:[/red] {e}")
        raise typer.Exit(1) from None
