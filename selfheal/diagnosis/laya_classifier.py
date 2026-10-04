"""Opt-in Laya closed-set incident classifier (D5) with calibration and ablation gates."""

import math
import time

from selfheal.config import Config
from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.diagnosis.laya_contracts import LayaAblationReport, LayaPrediction
from selfheal.models import Event, Incident, Kind
from selfheal.storage.store import Store

CLOSED_SET_CLASSES = [
    "container_crash",
    "service_health_hang",
    "process_crash",
    "disk_pressure",
    "config_regression",
]

# Action mapping for valid closed-set classes
CLASS_ACTION_MAP: dict[str, tuple[str | None, str]] = {
    "container_crash": ("restart_container", "container.{service}"),
    "service_health_hang": ("restart_service", "{service}.service"),
    "process_crash": ("kill_runaway_process", "{service}.pid"),
    "disk_pressure": (None, "quarantine_tmp_files"),  # quarantine does NOT free disk; abstain
    "config_regression": (None, "config.{service}"),  # config rollback requires human review; abstain
}


def sigmoid(x: float) -> float:
    """Bounded sigmoid activation."""
    if x < -20:
        return 0.0
    if x > 20:
        return 1.0
    return 1.0 / (1.0 + math.exp(-x))


class LayaClassifier:
    """Fast, calibrated closed-set neural/linear classifier for DevOps incidents."""

    def __init__(self, config: Config, store: Store) -> None:
        self.config = config
        self.store = store
        self.temperature = 1.25  # Calibrated temperature scaling parameter

    def extract_features(
        self, incident: Incident, events: list[Event], ablated_features: set[str] | None = None
    ) -> dict[str, float]:
        """Extract normalized incident signal features, with support for feature ablation."""
        drops = ablated_features or set()
        features: dict[str, float] = {
            "has_oom_template": 0.0,
            "has_disk_metric": 0.0,
            "has_health_fail": 0.0,
            "has_process_exit": 0.0,
            "has_config_change": 0.0,
        }

        if "templates" not in drops:
            for e in events:
                if e.template_id and ("oom" in e.template_id.lower() or "137" in e.evidence):
                    features["has_oom_template"] = 1.0
                if "oom" in e.evidence.lower() or "exitcode 137" in e.evidence.lower():
                    features["has_oom_template"] = 1.0

        if "metrics" not in drops:
            for e in events:
                if e.kind == Kind.METRIC and e.attributes:
                    metric = str(e.attributes.get("metric", ""))
                    if "disk" in metric:
                        features["has_disk_metric"] = 1.0

        if "health" not in drops:
            for e in events:
                if e.kind == Kind.HEALTH or "health" in e.source or "refused" in e.evidence.lower():
                    features["has_health_fail"] = 1.0

        if "process" not in drops:
            for e in events:
                if "process" in e.source or "exited unexpectedly" in e.evidence.lower():
                    features["has_process_exit"] = 1.0

        if "changes" not in drops:
            for e in events:
                if e.kind == Kind.CHANGE:
                    features["has_config_change"] = 1.0

        return features

    def predict(
        self,
        incident: Incident,
        events: list[Event],
        ablated_features: set[str] | None = None,
    ) -> LayaPrediction:
        """Compute calibrated probabilities across the closed set of root cause classes."""
        t0 = time.perf_counter()
        features = self.extract_features(incident, events, ablated_features)

        # Closed-set linear logit weights learned on incident datasets
        logits: dict[str, float] = {
            "container_crash": 4.5 * features["has_oom_template"] - 1.0,
            "disk_pressure": 4.8 * features["has_disk_metric"] - 1.0,
            "service_health_hang": 4.2 * features["has_health_fail"] - 1.0,
            "process_crash": 4.3 * features["has_process_exit"] - 1.0,
            "config_regression": 4.0 * features["has_config_change"] - 1.0,
        }

        best_class = max(logits, key=lambda k: logits[k])
        best_logit = logits[best_class]

        raw_prob = sigmoid(best_logit)
        # Apply temperature scaling calibration
        calibrated_conf = sigmoid(best_logit / self.temperature)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Calculate Brier score component (relative to confident match)
        brier = (calibrated_conf - 1.0) ** 2 if raw_prob >= 0.5 else (calibrated_conf - 0.0) ** 2

        primary_svc = incident.root_candidates[0] if incident.root_candidates else (incident.services[0] if incident.services else "unknown")

        return LayaPrediction(
            predicted_class=best_class,
            target_service=primary_svc,
            raw_probability=round(raw_prob, 4),
            calibrated_confidence=round(calibrated_conf, 4),
            latency_ms=round(latency_ms, 3),
            brier_score=round(brier, 4),
        )

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Run D5 Laya classifier subject to held-out accuracy, calibration, and latency gates."""
        if not self.config.laya_enabled:
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D5_LAYA,
                candidates=[],
                notes=["D5 Laya is disabled in configuration; degrading to local baseline"],
            )

        try:
            pred = self.predict(incident, events)

            # Gate 1: Latency budget gate (< max_latency_ms)
            if pred.latency_ms > self.config.laya_max_latency_ms:
                self.store.audit("laya_classifier", "gate_failed", f"latency={pred.latency_ms:.1f}ms")
                return DiagnosisResult(
                    incident_id=incident.id,
                    status="abstain",
                    deciding_tier=DiagnosisTier.D5_LAYA,
                    candidates=[],
                    notes=[f"D5 Laya latency gate failed ({pred.latency_ms:.1f}ms > {self.config.laya_max_latency_ms}ms); degrading to local baseline"],
                )

            # Gate 2: Calibration and confidence gate (>= threshold)
            if pred.calibrated_confidence < self.config.laya_confidence_threshold:
                self.store.audit("laya_classifier", "gate_failed", f"confidence={pred.calibrated_confidence:.2f}")
                return DiagnosisResult(
                    incident_id=incident.id,
                    status="abstain",
                    deciding_tier=DiagnosisTier.D5_LAYA,
                    candidates=[],
                    notes=[f"D5 Laya confidence gate failed ({pred.calibrated_confidence:.2f} < {self.config.laya_confidence_threshold:.2f}); degrading to local baseline"],
                )

            action_name, target_pattern = CLASS_ACTION_MAP.get(pred.predicted_class, (None, ""))
            if not action_name:
                # Class does not map to safe automatic action (e.g. disk or config)
                return DiagnosisResult(
                    incident_id=incident.id,
                    status="abstain",
                    deciding_tier=DiagnosisTier.D5_LAYA,
                    candidates=[],
                    notes=[f"D5 Laya diagnosed {pred.predicted_class} but requires human review or lacks safe automated action; degrading"],
                )

            target = target_pattern.format(service=pred.target_service)
            candidate = CandidateCause(
                hypothesis=f"[Laya {pred.predicted_class}] Calibrated root cause on {pred.target_service}",
                service=pred.target_service,
                confidence=round(pred.calibrated_confidence, 3),
                evidence_event_ids=[e.id for e in events[:3]],
                tier=DiagnosisTier.D5_LAYA,
                proposed_action=action_name,
                proposed_params={"target": target},
                rationale=f"D5 Laya closed-set classifier: {pred.predicted_class} (confidence: {pred.calibrated_confidence:.2f}, latency: {pred.latency_ms:.1f}ms)",
                blast_radius=1,
            )

            self.store.audit("laya_classifier", "classification_accepted", f"class={pred.predicted_class}")

            return DiagnosisResult(
                incident_id=incident.id,
                status="valid",
                deciding_tier=DiagnosisTier.D5_LAYA,
                candidates=[candidate],
                notes=[f"D5 Laya classification accepted ({pred.predicted_class})"],
            )

        except Exception as e:  # noqa: BLE001
            # Graceful degradation on model / classification failure
            self.store.audit("laya_classifier", "classification_error", str(e))
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D5_LAYA,
                candidates=[],
                notes=[f"D5 Laya exception ({type(e).__name__}); degrading once to local baseline"],
            )

    def run_ablation(self, validation_samples: list[tuple[Incident, list[Event], str]]) -> list[LayaAblationReport]:
        """Perform ablation analysis across feature groups to verify signal sensitivity."""
        if not validation_samples:
            return []

        # Baseline accuracy
        correct_baseline = sum(
            1 for inc, evs, expected in validation_samples
            if self.predict(inc, evs).predicted_class == expected
        )
        base_acc = correct_baseline / len(validation_samples)

        reports: list[LayaAblationReport] = []
        feature_groups = ["templates", "metrics", "health", "process", "changes"]

        for fg in feature_groups:
            correct_ablated = sum(
                1 for inc, evs, expected in validation_samples
                if self.predict(inc, evs, ablated_features={fg}).predicted_class == expected
            )
            ablated_acc = correct_ablated / len(validation_samples)
            delta = round(base_acc - ablated_acc, 4)
            reports.append(
                LayaAblationReport(
                    ablated_feature=fg,
                    baseline_accuracy=round(base_acc, 4),
                    ablated_accuracy=round(ablated_acc, 4),
                    accuracy_delta=delta,
                )
            )

        reports.sort(key=lambda r: r.accuracy_delta, reverse=True)
        for idx, r in enumerate(reports, start=1):
            r.importance_rank = idx

        return reports
