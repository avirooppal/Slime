"""Benchmark execution runner across enabled tiers and dataset adapters."""

import platform
import time
from collections.abc import Callable
from pathlib import Path

from selfheal.chaos.contracts import Scenario
from selfheal.config import Config, Service
from selfheal.correlator.engine import Correlator
from selfheal.eval.contracts import BenchmarkReport, TierMetrics
from selfheal.eval.dataset_adapters import DatasetAdapter, LocalCatalogAdapter
from selfheal.models import utcnow
from selfheal.planner.ranking import Planner
from selfheal.remediation.contracts import ActionBackend, Receipt, TargetParams
from selfheal.remediation.registry import default_registry
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import DiagnosisContext, Snapshot
from selfheal.safety.inventory import Inventory
from selfheal.safety.policy import Policy
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier


class BenchmarkFakeInventory(Inventory):
    """Deterministic inventory for benchmarking known scenario targets."""

    def __init__(self) -> None:
        self._targets: dict[str, Snapshot] = {
            "container.worker": Snapshot("container.worker", "container", "cnt-1", "rev-1", "crashed", False),
            "process.worker": Snapshot("process.worker", "process", "pid-1234", "rev-1", "running", False),
            "database": Snapshot("database", "systemd", "postgresql.service", "rev-1", "failed", False),
            "container.api": Snapshot("container.api", "container", "cnt-2", "rev-1", "running", False),
            "container.db": Snapshot("container.db", "container", "cnt-3", "rev-1", "running", False),
            "container.billing": Snapshot("container.billing", "container", "cnt-4", "rev-1", "running", False),
            "host": Snapshot("host", "host", "host-1", "rev-1", "running", False),
        }

    def snapshot(self, target: str) -> Snapshot:
        if target not in self._targets:
            raise LookupError(f"unknown target: {target}")
        return self._targets[target]

    def targets(self) -> set[str]:
        return set(self._targets.keys())


class BenchmarkFakeBackend(ActionBackend):
    """Safe action backend recording actions during benchmarking."""

    def __init__(self) -> None:
        self.executed_actions: list[str] = []

    def available(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        return True

    def execute(
        self, name: str, snapshot: Snapshot, params: TargetParams, stopped: Callable[[], bool]
    ) -> Receipt:
        self.executed_actions.append(f"{name}:{params.target}")
        return Receipt(f"benchmark:{name}")

    def verify(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        return True

    def rollback(
        self, name: str, snapshot: Snapshot, receipt: Receipt, stopped: Callable[[], bool]
    ) -> bool:
        return True


class BenchmarkRunner:
    """Executes reproducible incident scenarios across enabled tiers and measures metrics."""

    def __init__(
        self,
        config: Config | None = None,
        adapter: DatasetAdapter | None = None,
        tiers: list[str] | None = None,
    ) -> None:
        default_services = [
            Service(name="worker", container_name="worker-cnt", process_pid=1234),
            Service(name="database", journal_unit="postgresql.service"),
            Service(name="api", container_name="api-cnt"),
            Service(name="db", container_name="db-cnt"),
            Service(name="billing", container_name="billing-cnt"),
            Service(name="host"),
        ]
        if config is None:
            self.config = Config(
                dry_run=True,
                services=default_services,
                database=":memory:",
            )
        else:
            existing = {s.name: s for s in config.services}
            merged: list[Service] = []
            for d_svc in default_services:
                if d_svc.name in existing:
                    cur = existing[d_svc.name]
                    merged.append(
                        Service(
                            name=cur.name,
                            container_name=cur.container_name or d_svc.container_name,
                            journal_unit=cur.journal_unit or d_svc.journal_unit,
                            process_pid=cur.process_pid or d_svc.process_pid,
                            critical=cur.critical,
                            depends_on=cur.depends_on,
                            logs=cur.logs,
                            configs=cur.configs,
                            http_url=cur.http_url,
                            tcp_host=cur.tcp_host,
                            tcp_port=cur.tcp_port,
                            managed_process=cur.managed_process,
                        )
                    )
                else:
                    merged.append(d_svc)
            for name, cur in existing.items():
                if all(m.name != name for m in merged):
                    merged.append(cur)
            self.config = config.model_copy(update={"services": merged})
        self.adapter = adapter or LocalCatalogAdapter(include_adversarial=True)
        self.tiers_to_eval = tiers or ["D2_RUNBOOK", "COMBINED"]

    def evaluate_tier(self, tier_name: str, scenarios: list[Scenario]) -> TierMetrics:
        """Evaluate a single tier or combined system on all scenarios."""
        total_scenarios = len(scenarios)
        fault_scenarios = 0
        non_incident_scenarios = 0

        detected_count = 0
        diagnosed_correct = 0
        repaired_count = 0
        correct_fixes = 0
        authorized_count = 0
        false_incidents = 0
        false_positives = 0
        unsafe_attempts = 0
        latencies_ms: list[float] = []
        detection_ms: list[float] = []
        diagnosis_ms: list[float] = []
        tier_counts: dict[str, int] = {}

        registry = default_registry()
        inventory = BenchmarkFakeInventory()
        backend = BenchmarkFakeBackend()

        for scenario in scenarios:
            should_not_open = bool(
                getattr(scenario, "is_benign", False) or getattr(scenario, "adversarial", False)
            )
            if should_not_open:
                non_incident_scenarios += 1
            else:
                fault_scenarios += 1

            # Isolated in-memory store and correlator per scenario
            store = Store(":memory:")
            state = SafetyState(store)
            policy = Policy(registry, inventory, backend, state, self.config.safety, dry_run=False)
            correlator = Correlator(self.config, store)
            planner = Planner(registry, inventory)

            # Ingest events
            t0 = time.perf_counter()
            created_incident = None

            from selfheal.chaos.harness import ChaosHarness
            verifier = StabilityVerifier(window_seconds=1, interval_seconds=1, timeout_seconds=5)
            coord = Coordinator(
                config=self.config,
                store=store,
                inventory=inventory,
                backend=backend,
                state=state,
                verifier=verifier,
            )
            harness = ChaosHarness(workspace=Path("scratch/benchmark"), coordinator=coord)
            try:
                event = harness.inject(scenario)
                safe_event = store.event(event)
                inc = correlator.ingest(safe_event)
                if inc:
                    created_incident = inc
            finally:
                harness.cleanup()

            # Scenarios that should not open an incident are excluded from detection denominator
            # and reported separately as false-incident count/rate.
            if should_not_open:
                if created_incident:
                    false_incidents += 1
                    false_positives += 1
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                store.close()
                continue

            if not created_incident:
                # Missed detection on a true fault scenario
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                store.close()
                continue

            detected_count += 1
            detection_ms.append((time.perf_counter() - t0) * 1000.0)

            # Diagnosis evaluation
            diagnosis_started = time.perf_counter()
            diagnosis_result = None
            if tier_name == "D2_RUNBOOK":
                from selfheal.diagnosis.runbooks import RunbookEngine
                engine = RunbookEngine(self.config)
                events = store.incident_events(created_incident.id)
                diagnosis_result = engine.diagnose(created_incident, events)
            elif tier_name == "COMBINED":
                verifier = StabilityVerifier(window_seconds=1, interval_seconds=1, timeout_seconds=5)
                coord = Coordinator(
                    config=self.config,
                    store=store,
                    inventory=inventory,
                    backend=backend,
                    state=state,
                    verifier=verifier,
                )
                diagnosis_result = coord.diagnose_incident(created_incident)
            else:
                from selfheal.diagnosis.runbooks import RunbookEngine
                engine = RunbookEngine(self.config)
                events = store.incident_events(created_incident.id)
                diagnosis_result = engine.diagnose(created_incident, events)

            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            diagnosis_ms.append((time.perf_counter() - diagnosis_started) * 1000.0)

            if diagnosis_result:
                if diagnosis_result.status == "valid" and diagnosis_result.candidates:
                    tier_counts[diagnosis_result.deciding_tier] = (
                        tier_counts.get(diagnosis_result.deciding_tier, 0) + 1
                    )
                    top = diagnosis_result.candidates[0]
                    if top.service == scenario.expected_root_cause:
                        diagnosed_correct += 1
                    if scenario.expected_action is None and top.proposed_action is None:
                        correct_fixes += 1
                    elif scenario.expected_action is not None and top.proposed_action == scenario.expected_action:
                        correct_fixes += 1

                    ranked = planner.plan(diagnosis_result)
                    for r in ranked:
                        decision = policy.authorize(
                            r.proposal, DiagnosisContext(status="valid", incident_id=created_incident.id)
                        )
                        if getattr(scenario, "adversarial", False):
                            if decision.allowed:
                                unsafe_attempts += 1
                        elif decision.allowed:
                            authorized_count += 1
                            break
                elif diagnosis_result.status == "abstain" and scenario.expected_action is None:
                    # Score correct abstention as correct when no automated action is expected
                    diagnosed_correct += 1
                    correct_fixes += 1

            store.close()

        det_rate = (detected_count / fault_scenarios) if fault_scenarios > 0 else 1.0
        diag_match = (diagnosed_correct / detected_count) if detected_count > 0 else 0.0
        rep_rate = (repaired_count / fault_scenarios) if fault_scenarios > 0 else 0.0
        false_inc_rate = (false_incidents / non_incident_scenarios) if non_incident_scenarios > 0 else 0.0
        fp_rate = (false_positives / non_incident_scenarios) if non_incident_scenarios > 0 else 0.0
        unsafe_rate = (unsafe_attempts / total_scenarios) if total_scenarios > 0 else 0.0
        mean_lat = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

        return TierMetrics(
            tier=tier_name,
            total_scenarios=total_scenarios,
            fault_scenarios=fault_scenarios,
            non_incident_scenarios=non_incident_scenarios,
            detected_count=detected_count,
            detection_rate=round(det_rate, 4),
            diagnosed_correct_count=diagnosed_correct,
            diagnosis_match_rate=round(diag_match, 4),
            diagnosis_accuracy=round(diag_match, 4),
            repaired_count=repaired_count,
            repair_success_rate=round(rep_rate, 4),
            correct_fix_count=correct_fixes,
            correct_fix_rate=round(correct_fixes / fault_scenarios, 4) if fault_scenarios else 0.0,
            policy_authorized_count=authorized_count,
            false_incidents=false_incidents,
            false_incident_rate=round(false_inc_rate, 4),
            false_positives=false_positives,
            false_positive_rate=round(fp_rate, 4),
            unsafe_attempts=unsafe_attempts,
            unsafe_attempt_rate=round(unsafe_rate, 4),
            mean_latency_ms=round(mean_lat, 2),
            time_to_detect_ms=round(sum(detection_ms) / len(detection_ms), 2) if detection_ms else None,
            time_to_diagnose_ms=round(sum(diagnosis_ms) / len(diagnosis_ms), 2) if diagnosis_ms else None,
            time_to_recover_ms=None,
            resolved_without_llm_percent=None,
            deciding_tier_counts=tier_counts,
        )

    def run(self) -> BenchmarkReport:
        """Run 7-case smoke test or dataset adapter across configured tiers."""
        is_avail = self.adapter.is_available()
        scenarios: list[Scenario] = []
        notes = [
            self.adapter.documentation(),
            ("7-case smoke test scores detection, root-cause match, proposed fix/abstention match, "
             "false-incident rate, and policy only; no repair is executed, so recovery is unmeasured."),
        ]

        if is_avail:
            scenarios = self.adapter.load_scenarios()
        else:
            notes.append("Dataset not available; benchmark evaluated with 0 external samples.")

        tier_metrics_map: dict[str, TierMetrics] = {}
        for tier in self.tiers_to_eval:
            tier_metrics_map[tier] = self.evaluate_tier(tier, scenarios)

        overall = tier_metrics_map.get(
            "COMBINED",
            tier_metrics_map[self.tiers_to_eval[0]] if self.tiers_to_eval else TierMetrics(tier="NONE"),
        )

        return BenchmarkReport(
            timestamp=utcnow().isoformat(),
            environment=f"{platform.system()} {platform.machine()} Python {platform.python_version()}",
            dataset_name=self.adapter.name,
            dataset_license=self.adapter.license,
            dataset_available=is_avail,
            adapter_notes=notes,
            tiers=tier_metrics_map,
            overall=overall,
        )
