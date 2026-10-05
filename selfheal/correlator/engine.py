"""Time-window correlation, duplicate merging and maintenance suppression."""

from datetime import timedelta

from selfheal.config import Config
from selfheal.correlator.graph import DependencyGraph
from selfheal.models import Event, Incident, Kind, State, utcnow
from selfheal.storage.store import Store

ALLOWED = {
    State.OPEN: {State.INVESTIGATING, State.ESCALATED},
    State.INVESTIGATING: {State.MITIGATING, State.ESCALATED},
    State.MITIGATING: {State.VERIFYING, State.ESCALATED},
    State.VERIFYING: {State.RESOLVED, State.ESCALATED},
    State.RESOLVED: set(),
    State.ESCALATED: set(),
}


class Correlator:
    """Persist each incident update and its lifecycle decision atomically."""

    def __init__(self, config: Config, store: Store) -> None:
        """Restore incidents and use the configured dependency graph."""
        self.config, self.store = config, store
        self.graph = DependencyGraph(config.services)
        self.incidents = store.incidents()

    def transition(self, incident: Incident, state: State, reason: str) -> None:
        """Enforce lifecycle edges and append the human-readable reason."""
        if not reason.strip() or state not in ALLOWED[incident.state]:
            self.store.audit(incident.id, "invalid_transition", reason)
            raise ValueError("illegal transition or empty reason")
        previous = incident.state
        incident.state, incident.updated_at = state, utcnow()
        self.store.save_incident(incident)
        self.store.audit(
            incident.id, "state_transition", f"{previous.value}->{state.value}: {reason}"
        )
        for cached in self.incidents:
            if cached.id == incident.id and cached is not incident:
                cached.state, cached.updated_at = incident.state, incident.updated_at
                break

    def ingest(self, event: Event) -> Incident | None:
        """Group actionable signals; annotate maintenance without opening incidents."""
        if event.kind not in {Kind.ALERT, Kind.CHANGE, Kind.HEALTH}:
            return None
        if event.kind == Kind.HEALTH and event.attributes.get("healthy") is True:
            return None
        if event.kind == Kind.CHANGE and event.attributes.get("baseline") is True:
            return None
        if any(
            event.service in m.services and m.start <= event.timestamp < m.end
            for m in self.config.maintenance
        ):
            self.store.audit(
                event.id, "maintenance_suppressed", "signal retained; incident suppressed"
            )
            return None
        window = timedelta(seconds=self.config.correlation_seconds)
        matches = [
            i
            for i in self.incidents
            if i.state not in {State.RESOLVED, State.ESCALATED}
            and abs(event.timestamp - i.updated_at) <= window
            and any(self.graph.related(event.service, s) for s in i.services)
        ]
        if matches:
            incident = min(matches, key=lambda i: i.opened_at)
            for duplicate in matches:
                if duplicate.id == incident.id:
                    continue
                incident.event_ids = list(dict.fromkeys(incident.event_ids + duplicate.event_ids))
                incident.services = sorted(set(incident.services + duplicate.services))
                self.transition(duplicate, State.ESCALATED, f"merged into {incident.id}")
                self.store.audit(incident.id, "duplicate_merge", duplicate.id)
        else:
            incident = Incident(opened_at=event.timestamp, updated_at=event.timestamp)
            recent = [
                i
                for i in self.incidents
                if i.state == State.RESOLVED
                and event.service in i.services
                and timedelta(0) <= event.timestamp - i.updated_at <= window
            ]
            incident.flap_count = max((i.flap_count + 1 for i in recent), default=0)
            self.incidents.append(incident)
            self.store.audit(incident.id, "incident_opened", "new correlated signal")
        incident.services = sorted(set(incident.services + [event.service]))
        if event.id not in incident.event_ids:
            incident.event_ids.append(event.id)
        incident.updated_at = max(event.timestamp, incident.updated_at)
        incident.root_candidates = self.graph.roots(set(incident.services))
        incident.downstream = sorted(set(incident.services) - set(incident.root_candidates))
        if incident.flap_count:
            incident.notes = ["Repeated failure after resolution; possible flapping"]
        self.store.save_incident(incident)
        return incident
