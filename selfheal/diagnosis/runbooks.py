"""D2 declarative runbooks: rule-based root cause diagnosis."""

from selfheal.config import Config
from selfheal.correlator.graph import DependencyGraph
from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.models import Event, Incident, Kind


class RunbookEngine:
    """Evaluate deterministic runbook rules against correlated incident evidence."""

    def __init__(self, config: Config) -> None:
        """Initialize with configuration and dependency graph."""
        self.config = config
        self.graph = DependencyGraph(config.services)
        self.service_map = {s.name: s for s in config.services}

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Run declarative rules ordered by precision.

        Distinguishes root failures from downstream 5xx/health symptoms using
        the dependency graph and recent change events.
        """
        candidates: list[CandidateCause] = []
        notes: list[str] = []

        # Find root services vs downstream symptoms
        roots = set(incident.root_candidates)
        downstream = set(incident.downstream)

        # 1. Container crash / OOM rule
        crash_candidate = self._check_container_crash(incident, events, roots)
        if crash_candidate:
            candidates.append(crash_candidate)

        # 2. Service health check failure on root service
        service_candidate = self._check_service_failure(incident, events, roots, downstream)
        if service_candidate:
            candidates.append(service_candidate)

        # 3. Process failure / exit rule
        proc_candidate = self._check_process_failure(incident, events, roots)
        if proc_candidate:
            candidates.append(proc_candidate)

        # 4. Recent configuration change / regression
        change_candidate = self._check_config_change(incident, events, roots)
        if change_candidate:
            candidates.append(change_candidate)

        # 5. Disk pressure rule:
        # Note Phase 3 requirement: "A disk >90% alert may diagnose pressure but must
        # not propose the current quarantine action as capacity reclamation."
        disk_candidate = self._check_disk_pressure(incident, events)
        if disk_candidate:
            candidates.append(disk_candidate)

        if not candidates:
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D2_RUNBOOK,
                candidates=[],
                notes=["D2 runbooks: no matching rule signature with sufficient evidence"],
            )

        # Sort candidates by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)

        return DiagnosisResult(
            incident_id=incident.id,
            status="valid",
            deciding_tier=DiagnosisTier.D2_RUNBOOK,
            candidates=candidates,
            notes=notes or ["D2 runbook rules matched"],
        )

    def _check_container_crash(
        self, incident: Incident, events: list[Event], roots: set[str]
    ) -> CandidateCause | None:
        """Detect container crash or OOM exit from logs/health."""
        crash_events: list[Event] = []
        crashed_svc: str | None = None

        for e in events:
            # Check for container failure signals
            text = (e.evidence or "") + " " + str(e.attributes.get("reason", ""))
            text_lower = text.lower()
            if any(term in text_lower for term in ["oomkilled", "exitcode", "container exited", "crashed", "died"]):
                crash_events.append(e)
                if not crashed_svc:
                    crashed_svc = e.service
            elif e.kind == Kind.HEALTH and e.attributes.get("healthy") is False:
                svc_cfg = self.service_map.get(e.service)
                if svc_cfg and svc_cfg.container_name:
                    crash_events.append(e)
                    if not crashed_svc:
                        crashed_svc = e.service

        if not crash_events or not crashed_svc:
            return None

        # Determine target alias
        svc_cfg = self.service_map.get(crashed_svc)
        if not svc_cfg or not svc_cfg.container_name:
            return None

        target = f"container.{crashed_svc}"
        # If the crashed service is a root service, higher confidence
        is_root = crashed_svc in roots or not roots
        confidence = 0.95 if is_root else 0.85

        return CandidateCause(
            hypothesis=f"Container for {crashed_svc} crashed or exited abnormally",
            service=crashed_svc,
            confidence=confidence,
            evidence_event_ids=[e.id for e in crash_events],
            tier=DiagnosisTier.D2_RUNBOOK,
            proposed_action="restart_container",
            proposed_params={"target": target},
            rationale=f"Observed container exit/failure signals on {crashed_svc} ({'root' if is_root else 'downstream'})",
            blast_radius=1,
        )

    def _check_service_failure(
        self, incident: Incident, events: list[Event], roots: set[str], downstream: set[str]
    ) -> CandidateCause | None:
        """Detect service health probe failure on root service, avoiding downstream cascades."""
        failed_events_by_svc: dict[str, list[Event]] = {}
        for e in events:
            if (e.kind == Kind.HEALTH and e.attributes.get("healthy") is False) or (
                e.kind == Kind.ALERT and "health" in str(e.attributes.get("metric", ""))
            ):
                failed_events_by_svc.setdefault(e.service, []).append(e)

        if not failed_events_by_svc:
            return None

        # Prioritize root services over downstream services
        selected_svc: str | None = None
        for svc in incident.root_candidates:
            if svc in failed_events_by_svc:
                selected_svc = svc
                break

        if not selected_svc:
            # Check any root
            for svc in failed_events_by_svc:
                if svc in roots:
                    selected_svc = svc
                    break

        if not selected_svc:
            # Only downstream services failed, or no root found
            # If downstream failed because of an unmonitored dependency, propose human review with lower confidence
            candidate_svc = next(iter(failed_events_by_svc))
            evs = failed_events_by_svc[candidate_svc]
            svc_cfg = self.service_map.get(candidate_svc)
            target = candidate_svc
            action = "restart_service" if svc_cfg and svc_cfg.journal_unit else None
            return CandidateCause(
                hypothesis=f"Downstream service {candidate_svc} health failure (root cause may be upstream)",
                service=candidate_svc,
                confidence=0.70,  # Below auto-threshold 0.90 -> requires human review
                evidence_event_ids=[e.id for e in evs],
                tier=DiagnosisTier.D2_RUNBOOK,
                proposed_action=action,
                proposed_params={"target": target} if action else {},
                rationale="Only downstream symptom observed; potential upstream dependency failure",
                blast_radius=1,
            )

        evs = failed_events_by_svc[selected_svc]
        svc_cfg = self.service_map.get(selected_svc)
        target = selected_svc
        action = "restart_service" if svc_cfg and svc_cfg.journal_unit else "rerun_healthcheck"
        return CandidateCause(
            hypothesis=f"Root service {selected_svc} failed health check",
            service=selected_svc,
            confidence=0.92,
            evidence_event_ids=[e.id for e in evs],
            tier=DiagnosisTier.D2_RUNBOOK,
            proposed_action=action,
            proposed_params={"target": target},
            rationale=f"Health probe failure directly observed on dependency root {selected_svc}",
            blast_radius=1,
        )

    def _check_process_failure(
        self, incident: Incident, events: list[Event], roots: set[str]
    ) -> CandidateCause | None:
        """Detect process exit or runaway process."""
        proc_events: list[Event] = []
        for e in events:
            reason_str = str(e.attributes.get("reason") or "")
            if "process" in e.source or "process" in reason_str:
                proc_events.append(e)

        if not proc_events:
            return None

        e = proc_events[0]
        svc = e.service
        svc_cfg = self.service_map.get(svc)
        if not svc_cfg or not svc_cfg.process_pid:
            return None

        target = f"process.{svc}"
        return CandidateCause(
            hypothesis=f"Process failure detected for {svc}",
            service=svc,
            confidence=0.91,
            evidence_event_ids=[x.id for x in proc_events],
            tier=DiagnosisTier.D2_RUNBOOK,
            proposed_action="kill_runaway_process",
            proposed_params={"target": target},
            rationale=f"Process anomaly or unresponsiveness observed on {svc}",
            blast_radius=1,
        )

    def _check_config_change(
        self, incident: Incident, events: list[Event], roots: set[str]
    ) -> CandidateCause | None:
        """Detect recent configuration change correlated with failure."""
        change_events = [e for e in events if e.kind == Kind.CHANGE and not e.attributes.get("baseline")]
        if not change_events:
            return None

        e = change_events[0]
        svc = e.service
        return CandidateCause(
            hypothesis=f"Recent configuration change on {svc} caused regression",
            service=svc,
            confidence=0.85,  # Requires human review
            evidence_event_ids=[e.id],
            tier=DiagnosisTier.D2_RUNBOOK,
            proposed_action=None,  # No automated rollback without specific deployment adapter
            proposed_params={},
            rationale=f"Config modification event detected for {svc}; inspect change",
            blast_radius=1,
        )

    def _check_disk_pressure(self, incident: Incident, events: list[Event]) -> CandidateCause | None:
        """Detect disk usage > 90%.

        Per Phase 3 specifications:
        'A disk >90% alert may diagnose pressure but must not propose the current
        quarantine action as capacity reclamation.'
        Hence proposed_action is None (requires operator intervention).
        """
        disk_events = [
            e
            for e in events
            if e.kind == Kind.ALERT and str(e.attributes.get("metric", "")).startswith("disk_percent:")
        ]
        if not disk_events:
            return None

        e = disk_events[0]
        path = str(e.attributes.get("metric", "")).replace("disk_percent:", "")
        return CandidateCause(
            hypothesis=f"Disk space pressure on {path or 'host'} exceeding threshold",
            service=e.service,
            confidence=0.92,
            evidence_event_ids=[e.id for e in disk_events],
            tier=DiagnosisTier.D2_RUNBOOK,
            proposed_action=None,  # File quarantine does NOT reclaim disk; require human review
            proposed_params={},
            rationale=f"Disk usage alert triggered for {path}; automatic quarantine refused as it preserves bytes on disk",
            blast_radius=1,
        )
