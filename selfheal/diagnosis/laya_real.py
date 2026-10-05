"""Optional Laya Router triage gated by held-out evaluation evidence."""

import statistics
import time
import warnings
from pathlib import Path
from typing import Any

from selfheal.config import Config
from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.diagnosis.laya_contracts import (
    LayaAblationReport,
    LayaEvaluationReport,
    LayaPrediction,
)
from selfheal.models import Event, Incident
from selfheal.remediation.registry import default_registry
from selfheal.security import sanitize
from selfheal.storage.store import Store

INCIDENT_TYPES = {
    "container_crash": "Configured container exited or was OOM killed",
    "service_health_hang": "Configured service failed health checks",
    "process_crash": "Configured process exited unexpectedly",
    "disk_pressure": "Monitored disk has sustained capacity pressure",
    "config_regression": "Recent configuration change caused failures",
    "healthy_or_unknown": "Healthy, negated, historical or insufficient evidence",
}
ACTION_TARGETS = {
    "restart_container": ("container_crash", "container.{service}"),
    "restart_service": ("service_health_hang", "{service}"),
}


class LayaClassifier:
    """Use the English checkpoint only after a measured comparison passes."""

    def __init__(self, config: Config, store: Store, router: Any | None = None) -> None:
        self.config, self.store, self.router = config, store, router
        self._warned = False

    def _abstain(self, incident: Incident, reason: str) -> DiagnosisResult:
        """Continue with local tiers when optional inference is unavailable."""
        if self.config.laya_enabled and not self._warned:
            warnings.warn(f"Laya unavailable: {reason}; local diagnosis continues", stacklevel=2)
            self._warned = True
        return DiagnosisResult(incident_id=incident.id, status="abstain",
                               deciding_tier=DiagnosisTier.D5_LAYA, candidates=[], notes=[reason])

    def evaluation(self) -> LayaEvaluationReport | None:
        """Require an operator-selected held-out report and accuracy margin."""
        if not self.config.laya_eval_report or self.config.laya_required_accuracy_margin is None:
            return None
        try:
            report = LayaEvaluationReport.model_validate_json(
                Path(self.config.laya_eval_report).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if (report.model != "english" or
            report.accuracy < report.baseline_accuracy + self.config.laya_required_accuracy_margin or
            report.ece > report.baseline_ece or
            report.median_latency_ms >= report.baseline_median_latency_ms):
            return None
        return report

    def _router(self) -> Any:
        """Lazy-load laya.Router once; no package is needed in the default install."""
        if self.router is None:
            from laya import Router  # type: ignore[import-not-found]
            self.router = Router(default="english", max_loaded=1, preload=False)
        return self.router

    @staticmethod
    def questions() -> dict[str, dict[str, object]]:
        """Use Laya's four typed question heads with semantic labels."""
        return {
            "is_incident": {"type": "noul", "instructions":
                "Is there affirmative evidence of a current unhealthy configured service? Negated or healthy statements mean no."},
            "incident_type": {"type": "choice", "instructions":
                "Which root-cause class has direct current evidence?", "criteria": INCIDENT_TYPES},
            "severity": {"type": "score", "instructions": "How severe is the active incident?",
                         "criteria": ["informational", "degraded", "outage", "critical"]},
            "first_action": {"type": "choice", "instructions":
                "Which registered first action addresses the root cause? Choose human_review if uncertain.",
                "criteria": {**{name: name.replace("_", " ") for name in default_registry().actions},
                             "human_review": "No demonstrated safe first action"}},
        }

    @staticmethod
    def state_text(incident: Incident, events: list[Event]) -> str:
        """Bound and sanitize untrusted model observations."""
        lines = ["Services: " + ", ".join(incident.services[:10])]
        lines.extend(sanitize(
            f"{event.kind.value} {event.service} {event.source} {event.evidence[:256]}", 350)
            for event in events[:10])
        return "\n".join(lines)[:3000]

    def predict(self, incident: Incident, events: list[Event]) -> LayaPrediction:
        """Run one 512-token pass and gate on answer_confidence, not entropy."""
        start = time.perf_counter()
        result = self._router().predict(
            self.state_text(incident, events), self.questions(), model="english", max_len=512,
            min_confidence=self.config.laya_confidence_threshold)
        answers = result["answers"]
        if result.get("usage", {}).get("truncated") or result.get("usage", {}).get("state_tokens_dropped", 0):
            raise ValueError("Laya truncated evidence")
        incident_answer, type_answer, action_answer = (
            answers["is_incident"], answers["incident_type"], answers["first_action"])
        selected = (incident_answer, type_answer, action_answer)
        if (any(answer.get("low_confidence") for answer in selected) or
            float(incident_answer["noul"]) <= 0.5 or
            any(float(answer["answer_confidence"]) < self.config.laya_confidence_threshold
                for answer in selected)):
            raise ValueError("Laya abstained or returned low confidence")
        kind, action = str(type_answer["choice"]), str(action_answer["choice"])
        if kind not in INCIDENT_TYPES or action not in set(default_registry().actions) | {"human_review"}:
            raise ValueError("Laya returned unknown labels")
        if kind == "healthy_or_unknown" or action == "human_review":
            raise ValueError("Laya reported healthy or uncertain")
        if action not in ACTION_TARGETS or ACTION_TARGETS[action][0] != kind:
            raise ValueError("Laya action inconsistent with incident class")
        service = incident.root_candidates[0] if incident.root_candidates else (
            incident.services[0] if incident.services else "unknown")
        confidence = min(float(answer["answer_confidence"]) for answer in selected)
        return LayaPrediction(predicted_class=kind, target_service=service,
                              raw_probability=confidence, calibrated_confidence=confidence,
                              latency_ms=(time.perf_counter() - start) * 1000,
                              proposed_action=action)

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Shorten diagnosis only after the evaluation, confidence and latency gates."""
        if not self.config.laya_enabled:
            return self._abstain(incident, "D5 Laya disabled in configuration")
        if self.evaluation() is None:
            return self._abstain(incident, "D5 Laya held-out evaluation gate missing or failed")
        try:
            prediction = self.predict(incident, events)
            if prediction.latency_ms > self.config.laya_max_latency_ms:
                return self._abstain(incident, "D5 Laya latency limit exceeded")
            action = prediction.proposed_action
            assert action is not None
            candidate = CandidateCause(
                hypothesis=f"Laya class: {prediction.predicted_class}",
                service=prediction.target_service, confidence=prediction.calibrated_confidence,
                evidence_event_ids=[event.id for event in events[:5]], tier=DiagnosisTier.D5_LAYA,
                proposed_action=action,
                proposed_params={"target": ACTION_TARGETS[action][1].format(service=prediction.target_service)},
                rationale="Held-out gated Laya English-checkpoint classification")
            self.store.audit("laya_classifier", "classification_accepted", prediction.predicted_class)
            return DiagnosisResult(incident_id=incident.id, status="valid",
                                   deciding_tier=DiagnosisTier.D5_LAYA, candidates=[candidate])
        except Exception as exc:  # noqa: BLE001 - optional model must degrade
            self.store.audit("laya_classifier", "classification_error", type(exc).__name__)
            return self._abstain(incident, f"D5 Laya unavailable ({type(exc).__name__})")

    def run_ablation(
        self, samples: list[tuple[Incident, list[Event], str]]
    ) -> list[LayaAblationReport]:
        """Measure actual Router accuracy after removing each event category."""
        if not samples or self.evaluation() is None:
            return []

        def accuracy(drop: str | None) -> float:
            """Count abstentions as errors in this held-out comparison."""
            correct: list[bool] = []
            for incident, events, expected in samples:
                selected = [e for e in events if drop is None or e.kind.value != drop]
                try:
                    correct.append(self.predict(incident, selected).predicted_class == expected)
                except (ValueError, KeyError, TypeError):
                    correct.append(False)
            return statistics.mean(correct)

        baseline = accuracy(None)
        scores = {kind: accuracy(kind) for kind in ("log", "metric", "health", "change", "alert")}
        reports = [
            LayaAblationReport(
                ablated_feature=kind,
                baseline_accuracy=baseline,
                ablated_accuracy=scores[kind],
                accuracy_delta=baseline - scores[kind],
            )
            for kind in ("log", "metric", "health", "change", "alert")
        ]
        reports.sort(key=lambda report: report.accuracy_delta, reverse=True)
        for rank, report in enumerate(reports, 1):
            report.importance_rank = rank
        return reports
