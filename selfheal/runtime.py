"""Phase 3 runtime coordinator: polling, correlation, diagnosis, planning, safety, execution, and postmortem."""

import subprocess
import uuid
from typing import Protocol

from selfheal.collectors.changes import Changes
from selfheal.collectors.common import Warnings
from selfheal.collectors.health_checks import Health
from selfheal.collectors.journald import Journal
from selfheal.collectors.log_tailer import LogTailer
from selfheal.collectors.managed_process import ManagedProcessHealth
from selfheal.collectors.metrics import Metrics
from selfheal.config import Config, Service
from selfheal.correlator.engine import Correlator
from selfheal.diagnosis.contracts import DiagnosisResult, DiagnosisTier
from selfheal.diagnosis.retrieval import MemoryRetriever
from selfheal.diagnosis.runbooks import RunbookEngine
from selfheal.models import Event, Incident, Kind, State
from selfheal.notifications.contracts import NotificationLevel
from selfheal.planner.ranking import Planner, RankedProposal
from selfheal.postmortem.generator import PostmortemGenerator
from selfheal.remediation.contracts import ActionBackend
from selfheal.remediation.executor import ExecutionResult, Executor
from selfheal.remediation.managed_process import ManagedProcessSupervisor
from selfheal.remediation.native_backend import NativeBackend
from selfheal.remediation.registry import ActionRegistry, default_registry
from selfheal.safety.contracts import DiagnosisContext
from selfheal.safety.inventory import Inventory
from selfheal.safety.native_inventory import NativeInventory
from selfheal.safety.policy import Policy
from selfheal.safety.state import SafetyState
from selfheal.signals.anomaly import Anomalies
from selfheal.signals.templates import Templates
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier


class Collector(Protocol):
    """Independent bounded read-only event source."""

    def collect(self) -> list[Event]:
        """Return this poll's observations."""
        ...


class Monitor:
    """Coordinate collectors and detectors; provides read-only ingestion."""

    def __init__(self, config: Config, store: Store | None = None) -> None:
        """Initialize the local store and independently available collectors."""
        import importlib.util

        from selfheal.collectors.docker_logs import DockerLogs

        self.config = config
        self.store = store or Store(config.database)
        self.templates = Templates(self.store, learning_period=config.learning_period)
        self.anomalies = Anomalies(learning_period=config.learning_period)
        self.correlator = Correlator(config, self.store)
        self.managed_processes = ManagedProcessSupervisor(self.store)
        self.warnings = Warnings()
        self.collectors: list[tuple[str, Collector]] = []
        if config.metrics_enabled:
            self.collectors.append(("metrics", Metrics(config.disk_paths)))
        services = list(config.services)
        if not any(s.name == "host" for s in services):
            services.append(Service(name="host"))
        has_docker = importlib.util.find_spec("docker") is not None
        for service in services:
            self.collectors += [
                (f"health:{service.name}", Health(service)),
                (f"changes:{service.name}", Changes(service, self.store)),
            ]
            if service.managed_process is not None:
                self.collectors.append((
                    f"managed:{service.name}",
                    ManagedProcessHealth(service, self.managed_processes),
                ))
            for path in service.logs:
                self.collectors.append(
                    (f"file:{service.name}:{path}", LogTailer(path, service.name, self.store))
                )
            if service.container_name and has_docker:
                self.collectors.append(
                    (
                        f"docker_logs:{service.name}",
                        DockerLogs(service.container_name, service.name, self.store),
                    )
                )
            if service.journal_unit:
                try:
                    self.collectors.append(
                        (
                            f"journal:{service.name}",
                            Journal(service.journal_unit, service.name, self.store),
                        )
                    )
                except RuntimeError:
                    self.warnings.warn("journald", "journalctl missing")

    def ingest(self, event: Event) -> Incident | None:
        """Persist one signal and feed any derived alert into correlation."""
        alerts: list[Event] = []
        if event.kind == Kind.LOG:
            event, alerts = self.templates.process(event)
        elif event.kind == Kind.METRIC:
            metric = str(event.attributes["metric"])
            value = event.attributes["value"]
            if value is None:
                raise ValueError("metric value cannot be null")
            reason = self.anomalies.sample(
                event.service + ":" + metric,
                float(value),
                90 if metric.startswith("disk_percent:") else None,
            )
            if reason:
                alerts.append(
                    Event(
                        timestamp=event.timestamp,
                        kind=Kind.ALERT,
                        service=event.service,
                        source="anomaly",
                        attributes={**event.attributes, "reason": reason},
                        severity="warning",
                    )
                )
        last_incident = None
        for item in [event] + alerts:
            safe = self.store.event(item)
            inc = self.correlator.ingest(safe)
            if inc is not None:
                last_incident = inc
        return last_incident

    def poll(self) -> int:
        """Isolate collector failures and commit all successfully ingested events."""
        count = 0
        for name, collector in self.collectors:
            try:
                with self.store.connection:
                    events = collector.collect()
                    for event in events:
                        self.ingest(event)
                    count += len(events)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                self.warnings.warn(name, "read failed or target unavailable")
        return count

    def close(self) -> None:
        """Release database resources."""
        self.store.close()


class Coordinator:
    """End-to-end self-healing orchestrator wiring diagnosis, policy, execution, and verification."""

    def __init__(
        self,
        config: Config,
        store: Store | None = None,
        inventory: Inventory | None = None,
        backend: ActionBackend | None = None,
        registry: ActionRegistry | None = None,
        state: SafetyState | None = None,
        verifier: StabilityVerifier | None = None,
    ) -> None:
        """Initialize the single-process coordinator."""
        self.config = config
        self.store = store or Store(config.database)
        self.monitor = Monitor(config, self.store)
        self.state = state or SafetyState(self.store)
        self.registry = registry or default_registry()
        self.inventory = inventory or NativeInventory(config, store=self.store)
        self.backend = backend or NativeBackend(self.inventory)  # type: ignore[arg-type]
        self.policy = Policy(
            self.registry,
            self.inventory,
            self.backend,
            self.state,
            config.safety,
            dry_run=config.dry_run,
            max_auto_targets=config.max_auto_targets,
        )
        self.verifier = verifier or StabilityVerifier(
            window_seconds=config.stability_seconds,
            interval_seconds=config.safety.verification_interval_seconds,
            timeout_seconds=config.safety.verification_timeout_seconds,
            wait=self.state.stop.wait,
        )
        self.executor = Executor(self.policy, self.verifier, self.monitor.correlator)
        self.retriever = MemoryRetriever(self.store)
        self.runbooks = RunbookEngine(config)
        self.planner = Planner(self.registry, self.inventory)

        # Phase 6 Learning engine
        from selfheal.learning.contracts import LearningConfig
        from selfheal.learning.engine import LearningEngine

        learning_cfg = LearningConfig(
            min_samples=config.learning_min_samples,
            similarity_threshold=config.learning_similarity_threshold,
            enabled=config.learning_enabled,
        )
        self.learning = LearningEngine(self.store, learning_cfg)
        
        # D3 Local LLM investigator
        from selfheal.diagnosis.investigator import ModelInvestigator
        from selfheal.diagnosis.native_tools import NativeDiagnostics
        from selfheal.diagnosis.ollama_client import OllamaClient
        from selfheal.diagnosis.tools import ToolRunner

        ollama_client = OllamaClient(model=config.ollama_model)
        tool_runner = None
        if isinstance(self.inventory, NativeInventory):
            tool_runner = ToolRunner(NativeDiagnostics(self.inventory), self.store)
        self.investigator = ModelInvestigator(ollama_client, tool_runner)

        # Phase 8: D4 Cloud LLM and D5 Laya
        from selfheal.diagnosis.cloud_client import CloudInvestigator
        from selfheal.diagnosis.laya_classifier import LayaClassifier

        self.cloud_investigator = CloudInvestigator(config, self.store)
        self.laya = LayaClassifier(config, self.store)

        # Phase 9: Notifications engine
        from selfheal.notifications.engine import NotificationEngine

        self.notifications = NotificationEngine(self.store)

    def diagnose_incident(self, incident: Incident) -> DiagnosisResult:
        """Use proven memory and runbooks before optional model tiers."""
        events = self.store.incident_events(incident.id)

        # 1. Check if past verified fixes can safely shorten diagnosis
        shortcut = self.learning.evaluate_shortcut(incident, events)
        if shortcut.eligible and shortcut.candidate:
            result = DiagnosisResult(
                incident_id=incident.id,
                status="valid",
                deciding_tier=DiagnosisTier.D1_MEMORY,
                candidates=[shortcut.candidate],
                notes=shortcut.reasons,
            )
        else:
            result = DiagnosisResult(
                incident_id=incident.id, status="abstain", deciding_tier=DiagnosisTier.NONE,
                notes=["No diagnosis met the confidence threshold"],
            )
            for diagnose in (
                self.retriever.diagnose,
                self.runbooks.diagnose,
                self.laya.diagnose,
                self.investigator.diagnose,
                self.cloud_investigator.diagnose,
            ):
                attempt = diagnose(incident, events)
                if attempt.selected is None:
                    continue
                if result.selected is None or attempt.selected.confidence > result.selected.confidence:
                    result = attempt
                if attempt.selected.confidence >= self.config.safety.minimum_confidence:
                    result = attempt
                    break

        # Store hypotheses in DB
        for c in result.candidates:
            self.store.save_hypothesis(
                hypothesis_id=str(uuid.uuid4()),
                incident_id=incident.id,
                tier=c.tier,
                root_cause=c.hypothesis,
                action_name=c.proposed_action,
                target=str(c.proposed_params.get("target", "")) if c.proposed_params else None,
                params=c.proposed_params,
                confidence=c.confidence,
                payload=c.model_dump(mode="json"),
            )

        return result

    def handle_incident(
        self, incident: Incident
    ) -> tuple[DiagnosisResult, list[RankedProposal], ExecutionResult | None]:
        """Triage an incident: diagnose, plan, execute if authorized, and record postmortem."""
        # Must be in OPEN state to transition to INVESTIGATING
        if incident.state == State.OPEN:
            try:
                with self.store.connection:
                    self.monitor.correlator.transition(
                        incident, State.INVESTIGATING, "coordinator investigation started"
                    )
            except Exception:  # noqa: BLE001, S110
                pass

        diagnosis = self.diagnose_incident(incident)

        # Build historical success weights for planner
        success_weights: dict[str, float] = {}
        for out in self.store.verified_outcomes(only_stable=True):
            key = f"{out['action_name']}:{out['target']}"
            success_weights[key] = success_weights.get(key, 1.0) + 0.2

        ranked_proposals = self.planner.plan(diagnosis, success_weights)

        execution_result: ExecutionResult | None = None
        events = self.store.incident_events(incident.id)

        if not ranked_proposals:
            # No viable repair proposals
            if incident.state == State.INVESTIGATING:
                self.monitor.correlator.transition(
                    incident, State.ESCALATED, "no viable safe repair proposals"
                )
            self.notifications.notify(
                "incident_escalated",
                f"Incident Escalated: {incident.id}",
                f"No viable safe repair proposals for services: {', '.join(incident.services)}",
                NotificationLevel.WARNING,
            )
            md, payload = PostmortemGenerator.generate(incident, events, diagnosis, None)
            self.store.save_postmortem(incident.id, md, payload)
            return diagnosis, ranked_proposals, None

        # Take the top ranked proposal
        top_proposal = ranked_proposals[0].proposal
        top_candidate = ranked_proposals[0].candidate

        # Create trusted coordinator diagnosis context
        # Coordinator sets DiagnosisContext; diagnosis output itself must NOT set it
        context = DiagnosisContext(
            status="valid" if diagnosis.status == "valid" else "abstain",
            flapping=bool(incident.flap_count > 0),
            budget_exhausted=False,
            incident_id=incident.id,
        )

        execution_result = self.executor.run(top_proposal, context, incident)

        # If action was executed (not refused by dry-run/policy), record outcome in learning engine
        if execution_result.status != "refused":
            is_stable = bool(
                execution_result.status == "success"
                and execution_result.verification
                and execution_result.verification.stable
            )
            self.learning.record_outcome(
                incident=incident,
                events=events,
                action_name=top_proposal.name,
                target=str(top_proposal.params.get("target", "")),
                execution_status=execution_result.status,
                stable=is_stable,
                payload={
                    "rule": execution_result.rule,
                    "confidence": top_proposal.confidence,
                    "hypothesis": top_candidate.hypothesis,
                    "verification": (
                        {
                            "stable": execution_result.verification.stable,
                            "reason": execution_result.verification.reason,
                        }
                        if execution_result.verification
                        else None
                    ),
                },
            )
            self.notifications.notify(
                "repair_executed",
                f"Repair Executed: {incident.id}",
                f"Action {top_proposal.name} status={execution_result.status}, stable={is_stable}",
                NotificationLevel.INFO if is_stable else NotificationLevel.WARNING,
            )
        else:
            reason = execution_result.rule or ""
            if "breaker" in reason.lower():
                self.notifications.notify(
                    "breaker_tripped",
                    f"Circuit Breaker Tripped: {incident.id}",
                    f"Action {top_proposal.name} blocked: {reason}",
                    NotificationLevel.CRITICAL,
                )
            elif "approval" in reason.lower():
                self.state.stage_pending(top_proposal)
                self.notifications.notify(
                    "approval_required",
                    f"Approval Required: {incident.id}",
                    f"Action {top_proposal.name} requires human approval: {reason}",
                    NotificationLevel.WARNING,
                )

        # Generate and save postmortem
        md, payload = PostmortemGenerator.generate(incident, events, diagnosis, execution_result)
        self.store.save_postmortem(incident.id, md, payload)

        return diagnosis, ranked_proposals, execution_result

    def step(self) -> list[tuple[Incident, DiagnosisResult, list[RankedProposal], ExecutionResult | None]]:
        """Run one read-only poll cycle and process any open incidents."""
        self.monitor.poll()
        results = []
        for inc in list(self.monitor.correlator.incidents):
            if inc.state in {State.OPEN, State.INVESTIGATING}:
                diag, proposals, exec_res = self.handle_incident(inc)
                results.append((inc, diag, proposals, exec_res))
        return results

    def close(self) -> None:
        """Release underlying database and monitor resources."""
        self.monitor.close()
