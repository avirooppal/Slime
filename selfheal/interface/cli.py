"""Environment-aware setup, diagnosis, and CLI commands for Slime."""

import getpass
import importlib.util
import platform
import shutil
from pathlib import Path
from typing import Annotated

import httpx
import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from selfheal.config import Config, load_config
from selfheal.models import State
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import Proposal
from selfheal.safety.state import SafetyState, proposal_digest
from selfheal.storage.store import Store

app = typer.Typer(help="Slime: local-first, safety-first DevOps incident agent.")
console = Console()


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
def init(config: Path = Path("config.yaml")) -> None:
    """Detect capabilities and write explicit, dry-run configuration without overwriting."""
    if config.exists():
        console.print("Configuration exists; refusing to overwrite.", markup=False)
        raise typer.Exit(1)
    settings = Config(disk_paths=[Path.cwd().anchor])
    config.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    console.print(
        f"Created {config.absolute()} on {platform.system()}; dry-run enabled.", markup=False
    )
    console.print(
        "Configure named log files, services, dependencies and endpoints before monitoring."
    )
    console.print(
        f"journalctl: {'available' if shutil.which('journalctl') else 'unavailable on this host'}"
    )


@app.command()
def doctor(config: Path = Path("config.yaml")) -> None:
    """Report enabled sources, missing components and status of diagnosis tiers."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError):
        console.print("Invalid or missing configuration. Run selfheal init or correct config.yaml.")
        raise typer.Exit(1) from None
    table = Table("Component", "Status", "Reason")
    table.add_row(
        "Host metrics",
        "active" if settings.metrics_enabled else "disabled",
        "psutil; aggregate only",
    )
    for s in settings.services:
        for path in s.logs + s.configs:
            table.add_row(
                f"File ({s.name})", "active" if Path(path).is_file() else "unavailable", str(path)
            )
        if s.journal_unit:
            table.add_row(
                f"Journal ({s.name})",
                "active" if shutil.which("journalctl") else "unavailable",
                "requires journalctl",
            )
            table.add_row(
                f"Systemd ({s.name})",
                "active" if shutil.which("systemctl") else "unavailable",
                "requires systemctl",
            )
        if s.http_url or s.tcp_host or s.process_pid:
            table.add_row(
                f"Health ({s.name})", "configured", "endpoint or PID explicitly configured"
            )
    for extra, module in [
        ("docker", "docker"),
        ("dashboard", "fastapi"),
        ("embed", "sentence_transformers"),
        ("laya", "laya"),
    ]:
        table.add_row(
            extra,
            "installed" if importlib.util.find_spec(module) else "missing",
            "optional; not activated by the monitoring CLI",
        )
    try:
        with httpx.Client(timeout=1, trust_env=False) as client:
            response = client.get("http://127.0.0.1:11434/api/tags")
            response.raise_for_status()
        ollama = "reachable"
    except httpx.HTTPError:
        ollama = "unavailable (optional)"
    table.add_row("Ollama", ollama, settings.ollama_model + "; D3 active in Phase 5")
    table.add_row("Diagnosis D1/D2/D3", "active", "D1 memory, D2 runbooks, and D3 local LLM")
    d4_d5_status = "active" if (settings.cloud_enabled or settings.laya_enabled) else "disabled"
    d4_d5_reason = (
        "Phase 8; optional cloud/Laya active"
        if (settings.cloud_enabled or settings.laya_enabled)
        else "Phase 8; optional cloud/Laya not implemented / disabled by default"
    )
    table.add_row("D4/D5", d4_d5_status, d4_d5_reason)
    table.add_row(
        "Safety policy",
        "active",
        "deterministic; confidence >= " + str(settings.safety.minimum_confidence),
    )
    table.add_row(
        "Action registry", "9 typed actions", "SAFE/APPROVAL; exact live inventory required"
    )
    table.add_row(
        "Execution",
        "dry-run (default)" if settings.dry_run else "active mutation",
        "runtime CLI wired in Phase 3",
    )
    console.print(table)


@app.command()
def run(
    config: Path = Path("config.yaml"),
    dry_run: Annotated[bool | None, typer.Option("--dry-run/--no-dry-run", help="Override dry-run mode")] = None,
    once: Annotated[bool, typer.Option("--once", help="Run one cycle and exit")] = True,
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
        cycles = 1 if once else 999999
        for _ in range(cycles):
            results = coordinator.step()
            if not results:
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
    finally:
        coordinator.close()


@app.command()
def status(config: Path = Path("config.yaml")) -> None:
    """Display system status, circuit breaker, kill switch, and pending actions."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    store = Store(settings.database)
    state = SafetyState(store)
    try:
        killed = state.killed()
        circuit_open = state.circuit_open()
        recent_count = state.recent_count()

        table = Table(title="Safety Controls & Limits")
        table.add_column("Property", style="bold")
        table.add_column("Value")
        table.add_column("Detail")

        table.add_row("Kill switch", "[red]ACTIVE[/red]" if killed else "[green]INACTIVE[/green]", "Global mutation stop")
        table.add_row(
            "Circuit breaker",
            "[red]OPEN[/red]" if circuit_open else "[green]CLOSED[/green]",
            "Requires human reset if open",
        )
        table.add_row("Hourly auto count", str(recent_count), f"Max: {settings.safety.max_auto_per_hour}")
        table.add_row("Dry-run default", str(settings.dry_run), "Set in configuration")
        console.print(table)

        # Pending actions
        pending = store.connection.execute(
            "SELECT id, incident_id, name, target, started_at, status FROM actions WHERE status IN ('reserved','executing','verifying') ORDER BY started_at"
        ).fetchall()
        if pending:
            p_table = Table(title="Pending / Interrupted Actions")
            p_table.add_column("Action ID")
            p_table.add_column("Incident ID")
            p_table.add_column("Action")
            p_table.add_column("Target")
            p_table.add_column("Started At")
            p_table.add_column("Status", style="yellow")
            for r in pending:
                p_table.add_row(r[0], r[1], r[2], r[3], r[4], r[5])
            console.print(p_table)
    finally:
        store.close()


@app.command()
def incidents(
    config: Path = Path("config.yaml"),
    limit: Annotated[int, typer.Option("--limit", help="Max incidents to list")] = 10,
    show_postmortem: Annotated[str | None, typer.Option("--postmortem", help="Incident ID to display postmortem for")] = None,
) -> None:
    """List recent incidents or view postmortem for a specific incident."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    store = Store(settings.database)
    try:
        if show_postmortem:
            pm = store.postmortem(show_postmortem)
            if not pm:
                console.print(f"No postmortem found for incident {show_postmortem}.")
            else:
                console.print(pm["markdown"])
            return

        all_incidents = store.incidents()
        if not all_incidents:
            console.print("No incidents recorded.")
            return

        table = Table(title=f"Recent Incidents (Total: {len(all_incidents)})")
        table.add_column("ID", style="bold")
        table.add_column("State")
        table.add_column("Opened At (UTC)")
        table.add_column("Services")
        table.add_column("Root Candidates")
        table.add_column("Flaps")

        for inc in all_incidents[-limit:]:
            state_color = {
                State.OPEN: "yellow",
                State.INVESTIGATING: "blue",
                State.MITIGATING: "magenta",
                State.VERIFYING: "cyan",
                State.RESOLVED: "green",
                State.ESCALATED: "red",
            }.get(inc.state, "white")

            table.add_row(
                inc.id,
                f"[{state_color}]{inc.state.value}[/{state_color}]",
                inc.opened_at.strftime("%Y-%m-%d %H:%M:%S"),
                ", ".join(inc.services),
                ", ".join(inc.root_candidates),
                str(inc.flap_count),
            )
        console.print(table)
    finally:
        store.close()


@app.command()
def approve(
    incident_id: str,
    action: str,
    target: str,
    revision: str,
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
        console.print(f"Action: {action} on {target} (Revision: {revision})")
        console.print(f"Valid for {lifetime} seconds.")
    finally:
        store.close()


@app.command(name="dry-run")
def set_dry_run(
    enabled: Annotated[bool, typer.Argument(help="Enable (true) or disable (false) dry-run in config.yaml")],
    config: Path = Path("config.yaml"),
) -> None:
    """View or update dry-run configuration safely."""
    if not config.exists():
        console.print(f"Configuration file {config} not found.")
        raise typer.Exit(1)

    data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    data["dry_run"] = enabled
    config.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    console.print(f"Updated {config.name}: dry_run = {enabled}")


@app.command(name="kill-switch")
def kill_switch(
    enable: Annotated[bool, typer.Argument(help="True to engage kill switch, False to disengage")],
    config: Path = Path("config.yaml"),
    actor: Annotated[str | None, typer.Option("--actor", help="Operator username/identity")] = None,
) -> None:
    """Engage or disengage the global mutation kill switch."""
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
) -> None:
    """Run offline non-destructive chaos experiments and export JSONL ground truth."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    from selfheal.chaos.harness import ChaosHarness
    from selfheal.chaos.scenarios import adversarial_scenarios, standard_scenarios

    coordinator = Coordinator(settings)
    harness = ChaosHarness(scratch_dir, coordinator)
    all_scenarios = standard_scenarios() + adversarial_scenarios()
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
    """Run reproducible benchmarks across enabled tiers and report detection, repair, and safety metrics."""
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
        console.print(f"[green]Benchmark report exported to {output}[/green]")

    if json_output:
        console.print(report.model_dump_json(indent=2))
        return

    console.print(f"\n[bold]Dataset:[/bold] {report.dataset_name} ({report.dataset_license})")
    for note in report.adapter_notes:
        console.print(f"[dim]{note}[/dim]")

    table = Table(title="\nBenchmark Evaluation by Tier")
    table.add_column("Tier", style="bold", no_wrap=True)
    table.add_column("Total", justify="right")
    table.add_column("Detection", justify="right")
    table.add_column("Diag Acc", justify="right")
    table.add_column("Repair Rate", justify="right")
    table.add_column("FP Rate", justify="right")
    table.add_column("Unsafe Attr", justify="right")
    table.add_column("Latency (ms)", justify="right")

    for tier_name, m in report.tiers.items():
        unsafe_styled = f"[green]{m.unsafe_attempt_rate:.1%}[/green]" if m.unsafe_attempts == 0 else f"[red]{m.unsafe_attempt_rate:.1%}[/red]"
        table.add_row(
            tier_name,
            str(m.total_scenarios),
            f"{m.detection_rate:.1%}",
            f"{m.diagnosis_accuracy:.1%}",
            f"{m.repair_success_rate:.1%}",
            f"{m.false_positive_rate:.1%}",
            unsafe_styled,
            f"{m.mean_latency_ms:.1f}",
        )

    console.print(table)


@app.command()
def dashboard(
    config: Path = Path("config.yaml"),
    host: Annotated[str, typer.Option("--host", help="Binding host (strictly localhost-only)")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port to listen on")] = 8080,
) -> None:
    """Launch the optional one-page localhost-only FastAPI dashboard."""
    try:
        settings = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Error loading config:[/red] {e}")
        raise typer.Exit(1) from None

    if host not in ("127.0.0.1", "localhost"):
        console.print(
            f"[red]Security error:[/red] Host '{host}' is forbidden. Dashboard is strictly localhost-only (127.0.0.1)."
        )
        raise typer.Exit(1)

    try:
        from selfheal.interface.dashboard import run_dashboard

        console.print(f"[green]Starting Slime Dashboard on http://{host}:{port}...[/green]")
        run_dashboard(settings, host=host, port=port)
    except ImportError as e:
        console.print(f"[yellow]Dashboard optional dependencies not installed:[/yellow] {e}")
        console.print("Install with: [bold]pip install -e '.[dashboard]'[/bold]")
        raise typer.Exit(1) from None
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Dashboard failed to start:[/red] {e}")
        raise typer.Exit(1) from None


