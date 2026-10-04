"""Benchmark execution runner across enabled tiers and dataset adapters."""

import platform
import time
from pathlib import Path

from selfheal.chaos.contracts import Scenario
from selfheal.config import Config, Service
from selfheal.correlator.engine import Correlator
from selfheal.eval.contracts import BenchmarkReport, TierMetrics
from selfheal.eval.dataset_adapters import DatasetAdapter, LocalCatalogAdapter
from selfheal.models import utcnow
from selfheal.planner.ranking import Planner
from selfheal.remediation.contracts import ActionBackend
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
            "container.api": Snapshot("container.api", "container", "cnt-2", "rev-1", "running", False),
            "container.db": Snapshot("container.db", "container", "cnt-3", "rev-1", "running", False),
            "container.billing": Snapshot("container.billing", "container", "cnt-4", "rev-1", "running", False),
        }

    def snapshot(self, target: str) -> Snapshot:
        if target not in self._targets:
            raise LookupError(f"unknown target: {target}")
        return self._targets[target]

    def targets(self) -> set[str]:
        return set(self._targets.keys())


from collections.abc import Callable

from selfheal.remediation.contracts import Receipt, TargetParams


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
        self.config = config or Config(
            dry_run=True,
            services=[
                Service(name="worker", container_name="worker-cnt"),
                Service(name="api", container_name="api-cnt"),
                Service(name="db", container_name="db-cnt"),
                Service(name="billing", container_name="billing-cnt"),
            ],
            database=":memory:",
        )
        self.adapter = adapter or LocalCatalogAdapter(include_adversarial=True)
        self.tiers_to_eval = tiers or ["D2_RUNBOOK", "COMBINED"]

    def evaluate_tier(self, tier_name: str, scenarios: list[Scenario]) -> TierMetrics:
        """Evaluate a single tier or combined system on all scenarios."""
        total_scenarios = len(scenarios)
        fault_scenarios = 0
        benign_scenarios = 0

        detected_count = 0
        diagnosed_correct = 0
        repaired_count = 0
        false_positives = 0
        unsafe_attempts = 0
        latencies_ms: list[float] = []

        registry = default_registry()
        inventory = BenchmarkFakeInventory()
        backend = BenchmarkFakeBackend()

        for scenario in scenarios:
            is_benign = getattr(scenario, "is_benign", False)
            if is_benign:
                benign_scenarios += 1
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

            # Detection evaluation
            if is_benign:
                if created_incident:
                    false_positives += 1
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                store.close()
                continue

            if not created_incident:
                # Missed detection
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                store.close()
                continue

            detected_count += 1

            # Diagnosis evaluation
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
                # Fallback to runbooks
                from selfheal.diagnosis.runbooks import RunbookEngine
                engine = RunbookEngine(self.config)
                events = store.incident_events(created_incident.id)
                diagnosis_result = engine.diagnose(created_incident, events)

            latencies_ms.append((time.perf_counter() - t0) * 1000.0)

            if diagnosis_result and diagnosis_result.status == "valid" and diagnosis_result.candidates:
                top = diagnosis_result.candidates[0]
                # Check root cause identification
                if top.service == scenario.target_service or (
                    hasattr(scenario, "expected_root_cause")
                    and top.proposed_action == scenario.expected_root_cause
                ):
                    diagnosed_correct += 1

                # Safety & planning check: ensure no adversarial command was accepted
                ranked = planner.plan(diagnosis_result)
                for r in ranked:
                    decision = policy.authorize(r.proposal, DiagnosisContext(status="valid", incident_id=created_incident.id))
                    # Check invariant: unsafe attempts
                    if getattr(scenario, "adversarial", False):
                        if decision.allowed:
                            unsafe_attempts += 1
                    elif decision.allowed:
                        repaired_count += 1
                        break

            store.close()

        det_rate = (detected_count / fault_scenarios) if fault_scenarios > 0 else 1.0
        diag_acc = (diagnosed_correct / detected_count) if detected_count > 0 else 0.0
        rep_rate = (repaired_count / fault_scenarios) if fault_scenarios > 0 else 0.0
        fp_rate = (false_positives / benign_scenarios) if benign_scenarios > 0 else 0.0
        unsafe_rate = (unsafe_attempts / total_scenarios) if total_scenarios > 0 else 0.0
        mean_lat = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

        return TierMetrics(
            tier=tier_name,
            total_scenarios=total_scenarios,
            detected_count=detected_count,
            detection_rate=round(det_rate, 4),
            diagnosed_correct_count=diagnosed_correct,
            diagnosis_accuracy=round(diag_acc, 4),
            repaired_count=repaired_count,
            repair_success_rate=round(rep_rate, 4),
            false_positives=false_positives,
            false_positive_rate=round(fp_rate, 4),
            unsafe_attempts=unsafe_attempts,
            unsafe_attempt_rate=round(unsafe_rate, 4),
            mean_latency_ms=round(mean_lat, 2),
        )

    def run(self) -> BenchmarkReport:
        """Run benchmark suite across configured dataset adapter and tiers."""
        is_avail = self.adapter.is_available()
        scenarios: list[Scenario] = []
        notes = [self.adapter.documentation()]

        if is_avail:
            scenarios = self.adapter.load_scenarios()
        else:
            notes.append("Dataset not available; benchmark evaluated with 0 external samples.")

        tier_metrics_map: dict[str, TierMetrics] = {}
        for tier in self.tiers_to_eval:
            tier_metrics_map[tier] = self.evaluate_tier(tier, scenarios)

        # Compute overall metrics
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
