"""D1 Memory: BM25 retrieval over historical verified incident outcomes."""

from rank_bm25 import BM25Plus

from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.models import Event, Incident
from selfheal.storage.store import Store


def extract_incident_features(incident: Incident, events: list[Event]) -> list[str]:
    """Tokenize template IDs, service/dependency context, changes and metric patterns."""
    tokens: list[str] = []
    # Service tokens
    for s in incident.services:
        tokens.append(f"svc:{s}")
    for s in incident.root_candidates:
        tokens.append(f"root_candidate:{s}")
    for s in incident.downstream:
        tokens.append(f"downstream:{s}")

    # Event tokens
    for e in events:
        tokens.append(f"kind:{e.kind.value}")
        tokens.append(f"event_svc:{e.service}")
        if e.template_id:
            tokens.append(f"template:{e.template_id}")
        if e.severity:
            tokens.append(f"sev:{e.severity}")
        if e.attributes:
            metric = e.attributes.get("metric")
            if metric:
                tokens.append(f"metric:{metric}")
            reason = e.attributes.get("reason")
            if reason:
                tokens.append(f"reason:{reason}")
            change_type = e.attributes.get("change")
            if change_type:
                tokens.append(f"change:{change_type}")

    return tokens


class MemoryRetriever:
    """Historical incident diagnosis via BM25 over verified successful outcomes."""

    def __init__(self, store: Store, min_score: float = 1.0) -> None:
        """Initialize with local store and minimum BM25 score threshold."""
        self.store = store
        self.min_score = min_score

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Query historical verified outcomes. On cold start or low match, cleanly abstain."""
        verified = self.store.verified_outcomes(only_stable=True)
        if not verified:
            # Clean cold-start abstention
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D1_MEMORY,
                candidates=[],
                notes=["D1 memory cold start: no historical verified outcomes"],
            )

        # Build corpus tokens for each verified outcome
        corpus: list[list[str]] = []
        for out in verified:
            doc_tokens: list[str] = []
            template_ids = out.get("template_ids")
            if isinstance(template_ids, list):
                for t_id in template_ids:
                    doc_tokens.append(f"template:{t_id}")
            services = out.get("services")
            if isinstance(services, list):
                for s in services:
                    doc_tokens.append(f"svc:{s}")
            changes = out.get("changes")
            if isinstance(changes, list):
                for c in changes:
                    doc_tokens.append(f"change:{c}")
            metrics_pattern = out.get("metrics_pattern")
            if isinstance(metrics_pattern, list):
                for m in metrics_pattern:
                    doc_tokens.append(f"metric:{m}")
            corpus.append(doc_tokens)

        # Build query tokens from current incident
        query_tokens = extract_incident_features(incident, events)
        if not query_tokens:
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D1_MEMORY,
                candidates=[],
                notes=["D1 memory: insufficient query features for matching"],
            )

        bm25 = BM25Plus(corpus)
        scores = bm25.get_scores(query_tokens)

        # Find best match
        best_idx = int(scores.argmax())
        best_score = float(scores[best_idx])

        if best_score < self.min_score:
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D1_MEMORY,
                candidates=[],
                notes=[f"D1 memory score {best_score:.2f} below threshold {self.min_score:.2f}"],
            )

        matched = verified[best_idx]
        action_name = str(matched["action_name"])
        target = str(matched["target"])
        confidence = min(0.95, 0.70 + (best_score / (best_score + 10.0)) * 0.25)

        # Collect event IDs that contributed to the match
        matched_event_ids: list[str] = []
        matched_templates = set(matched["template_ids"]) if isinstance(matched["template_ids"], list) else set()
        matched_services = set(matched["services"]) if isinstance(matched["services"], list) else set()
        for e in events:
            if (e.template_id and e.template_id in matched_templates) or e.service in matched_services:
                matched_event_ids.append(e.id)

        matched_svc_list = matched.get("services")
        matched_svc = (
            str(matched_svc_list[0])
            if isinstance(matched_svc_list, list) and matched_svc_list
            else incident.services[0]
        )

        candidate = CandidateCause(
            hypothesis=f"Recurring incident matching historical {matched['incident_id']}",
            service=matched_svc,
            confidence=round(confidence, 3),
            evidence_event_ids=matched_event_ids,
            tier=DiagnosisTier.D1_MEMORY,
            proposed_action=action_name,
            proposed_params={"target": target},
            rationale=f"BM25 match against verified incident {matched['incident_id']} with score {best_score:.2f}",
            blast_radius=1,
        )

        return DiagnosisResult(
            incident_id=incident.id,
            status="valid",
            deciding_tier=DiagnosisTier.D1_MEMORY,
            candidates=[candidate],
            notes=[f"D1 memory matched historical outcome {matched['id']}"],
        )
