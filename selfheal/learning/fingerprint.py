"""Feature extraction and fingerprinting for incidents."""

from selfheal.learning.contracts import ContextFingerprint
from selfheal.models import Event, Incident, Kind


def extract_fingerprint(incident: Incident, events: list[Event]) -> ContextFingerprint:
    """Extract canonical context fingerprint from an incident and its associated events."""
    primary_service = (
        incident.root_candidates[0]
        if incident.root_candidates
        else (incident.services[0] if incident.services else "unknown")
    )

    template_ids: set[str] = set()
    metric_signatures: set[str] = set()
    change_signatures: set[str] = set()
    event_kinds: set[str] = set()

    for e in events:
        event_kinds.add(e.kind.value)
        if e.template_id:
            template_ids.add(e.template_id)
        if e.kind == Kind.METRIC and e.attributes:
            metric = e.attributes.get("metric")
            if metric:
                sev = e.severity or "info"
                metric_signatures.add(f"{metric}:{sev}")
        if e.kind == Kind.CHANGE and e.attributes:
            change_type = e.attributes.get("change")
            if change_type:
                change_signatures.add(f"{change_type}:{e.service}")

    return ContextFingerprint(
        primary_service=primary_service,
        services=sorted(set(incident.services)),
        root_candidates=sorted(set(incident.root_candidates)),
        downstream=sorted(set(incident.downstream)),
        template_ids=sorted(template_ids),
        metric_signatures=sorted(metric_signatures),
        change_signatures=sorted(change_signatures),
        event_kinds=sorted(event_kinds),
    )


def reconstruct_fingerprint(outcome: dict[str, object]) -> ContextFingerprint:
    """Reconstruct ContextFingerprint from a persisted verified outcome dict."""
    payload = outcome.get("payload")
    if isinstance(payload, dict):
        fp_dict = payload.get("fingerprint")
        if isinstance(fp_dict, dict):
            try:
                return ContextFingerprint.model_validate(fp_dict)
            except Exception:  # noqa: BLE001, S110
                pass

    # Fall back to reconstructing from legacy flat outcome fields
    services = outcome.get("services")
    svc_list = [str(s) for s in services] if isinstance(services, list) else []
    templates = outcome.get("template_ids")
    tpl_list = [str(t) for t in templates] if isinstance(templates, list) else []
    metrics = outcome.get("metrics_pattern")
    metric_list = [str(m) for m in metrics] if isinstance(metrics, list) else []
    changes = outcome.get("changes")
    change_list = [str(c) for c in changes] if isinstance(changes, list) else []

    primary_service = svc_list[0] if svc_list else "unknown"

    return ContextFingerprint(
        primary_service=primary_service,
        services=sorted(svc_list),
        root_candidates=[primary_service] if primary_service != "unknown" else [],
        downstream=[],
        template_ids=sorted(tpl_list),
        metric_signatures=sorted(metric_list),
        change_signatures=sorted(change_list),
        event_kinds=["alert"],
    )
