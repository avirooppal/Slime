"""Learning engine: context fingerprinting, sample thresholding, and shortcut evaluation."""

import uuid
from typing import Any

from selfheal.diagnosis.contracts import CandidateCause, DiagnosisTier
from selfheal.learning.contracts import LearningConfig, ShortcutDecision
from selfheal.learning.fingerprint import extract_fingerprint, reconstruct_fingerprint
from selfheal.models import Event, Incident
from selfheal.storage.store import Store


class LearningEngine:
    """Manages context fingerprints, verified outcome records, and diagnosis shortcut gates."""

    def __init__(self, store: Store, config: LearningConfig | None = None) -> None:
        """Initialize with event store and learning configuration."""
        self.store = store
        self.config = config or LearningConfig()

    def record_outcome(
        self,
        incident: Incident,
        events: list[Event],
        action_name: str,
        target: str,
        execution_status: str,
        stable: bool,
        payload: dict[str, Any] | None = None,
    ) -> None:
        """Record an executed remediation outcome with its context fingerprint.

        Invariant: No failed or unstable outcome ever counts as success.
        """
        fingerprint = extract_fingerprint(incident, events)
        # Strict invariant: only completely successful execution with verified stability is stable
        is_stable = bool(execution_status == "success" and stable)

        template_ids = [e.template_id for e in events if e.template_id]
        changes = [
            str(e.attributes.get("change"))
            for e in events
            if e.attributes and e.attributes.get("change")
        ]
        metrics_pattern = [
            str(e.attributes.get("metric"))
            for e in events
            if e.attributes and e.attributes.get("metric")
        ]

        outcome_payload: dict[str, Any] = payload.copy() if payload else {}
        outcome_payload["fingerprint"] = fingerprint.model_dump()
        outcome_payload["execution_status"] = execution_status

        self.store.save_verified_outcome(
            outcome_id=str(uuid.uuid4()),
            incident_id=incident.id,
            action_name=action_name,
            target=target,
            template_ids=template_ids,
            services=incident.services,
            changes=changes,
            metrics_pattern=metrics_pattern,
            stable=is_stable,
            payload=outcome_payload,
            fingerprint=fingerprint.fingerprint_hash,
        )

    def evaluate_shortcut(self, incident: Incident, events: list[Event]) -> ShortcutDecision:
        """Determine whether past verified fixes can safely shorten diagnosis.

        Enforces:
        1. Clean cold start abstention if no historical outcomes exist.
        2. Minimum sample count: at least config.min_samples verified stable outcomes.
        3. Similarity threshold: context fingerprint similarity >= config.similarity_threshold.
        4. No failed or unstable outcome counts as success; any failure blocks shortcutting.
        5. Context shift detection: symptom/topology/metric shift forces full diagnosis.
        """
        current_fp = extract_fingerprint(incident, events)

        if not self.config.enabled:
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                reasons=["Learning engine disabled by configuration; forcing full diagnosis"],
                fingerprint=current_fp,
            )

        all_outcomes = self.store.verified_outcomes(only_stable=False)
        if not all_outcomes:
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                reasons=["Cold start: no historical outcomes recorded; forcing full diagnosis"],
                fingerprint=current_fp,
            )

        # Track outcomes grouped by (action_name, target)
        # Group stats: { (action, target): { "stable": int, "failed": int, "best_sim": float, "shift": bool, "shift_reasons": list[str] } }
        groups: dict[tuple[str, str], dict[str, Any]] = {}

        for out in all_outcomes:
            action_name = str(out["action_name"])
            target = str(out["target"])
            key = (action_name, target)

            if key not in groups:
                groups[key] = {
                    "stable": 0,
                    "failed": 0,
                    "best_sim": 0.0,
                    "shift": False,
                    "shift_reasons": [],
                    "matched_outcomes": [],
                }

            stored_fp = reconstruct_fingerprint(out)
            sim = current_fp.similarity(stored_fp)
            is_shifted, shift_reasons = stored_fp.detect_shift(current_fp)

            has_service_overlap = bool(
                set(current_fp.services) & set(stored_fp.services)
                or current_fp.primary_service in stored_fp.services
                or stored_fp.primary_service in current_fp.services
            )

            if is_shifted and (has_service_overlap or sim >= 0.5):
                groups[key]["shift"] = True
                groups[key]["shift_reasons"].extend(shift_reasons)
                groups[key]["best_sim"] = max(groups[key]["best_sim"], sim)
            elif sim >= self.config.similarity_threshold and not is_shifted:
                groups[key]["best_sim"] = max(groups[key]["best_sim"], sim)
                if out["stable"]:
                    groups[key]["stable"] += 1
                    groups[key]["matched_outcomes"].append(out)
                else:
                    groups[key]["failed"] += 1

        active_groups = {
            k: v for k, v in groups.items()
            if v["shift"] or v["stable"] > 0 or v["failed"] > 0
        }

        if not active_groups:
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                reasons=[f"No historical outcomes met similarity threshold {self.config.similarity_threshold:.2f}; forcing full diagnosis"],
                fingerprint=current_fp,
            )

        # Pick group with shift prioritized (to explain shift), else highest stable count
        best_key = max(
            active_groups.keys(),
            key=lambda k: (1 if active_groups[k]["shift"] else 0, active_groups[k]["stable"], active_groups[k]["best_sim"]),
        )
        best_stats = active_groups[best_key]
        action_name, target = best_key

        best_sim = float(best_stats["best_sim"])
        stable_count = int(best_stats["stable"])
        failed_count = int(best_stats["failed"])
        shift_detected = bool(best_stats["shift"])
        shift_reasons = list(best_stats["shift_reasons"])

        # Check 1: Context shift detection
        if shift_detected:
            reasons = [
                f"Context shift detected ({'; '.join(shift_reasons)}); forcing full diagnosis"
            ]
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                sample_count=stable_count,
                failed_count=failed_count,
                best_similarity=best_sim,
                shift_detected=True,
                reasons=reasons,
                fingerprint=current_fp,
            )

        # Check 2: No failed/unstable outcome counts as success
        if failed_count > 0:
            reasons = [
                f"Historical failed or unstable outcomes detected ({failed_count}); forcing full diagnosis"
            ]
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                sample_count=stable_count,
                failed_count=failed_count,
                best_similarity=best_sim,
                shift_detected=False,
                reasons=reasons,
                fingerprint=current_fp,
            )

        # Check 3: Minimum sample count
        if stable_count < self.config.min_samples:
            reasons = [
                f"Insufficient verified samples ({stable_count} < min {self.config.min_samples}); forcing full diagnosis"
            ]
            return ShortcutDecision(
                eligible=False,
                shortened=False,
                sample_count=stable_count,
                failed_count=failed_count,
                best_similarity=best_sim,
                shift_detected=False,
                reasons=reasons,
                fingerprint=current_fp,
            )

        # All criteria satisfied: Safe shortcut authorized
        confidence = min(
            0.98,
            0.90
            + 0.02 * min(5, stable_count - self.config.min_samples)
            + 0.04 * (best_sim - self.config.similarity_threshold),
        )

        matched_event_ids: list[str] = []
        for e in events:
            if (e.template_id and e.template_id in current_fp.template_ids) or e.service in current_fp.services:
                matched_event_ids.append(e.id)

        candidate = CandidateCause(
            hypothesis=f"Learned repair verified across {stable_count} identical past incidents",
            service=current_fp.primary_service,
            confidence=round(confidence, 3),
            evidence_event_ids=matched_event_ids,
            tier=DiagnosisTier.D1_MEMORY,
            proposed_action=action_name,
            proposed_params={"target": target},
            rationale=f"Learning shortcut: {stable_count} verified stable outcomes with similarity {best_sim:.2f} >= {self.config.similarity_threshold:.2f}",
            blast_radius=1,
        )

        return ShortcutDecision(
            eligible=True,
            shortened=True,
            candidate=candidate,
            sample_count=stable_count,
            failed_count=0,
            best_similarity=best_sim,
            shift_detected=False,
            reasons=[
                f"Learning shortcut authorized: {stable_count} verified outcomes (similarity {best_sim:.2f})"
            ],
            fingerprint=current_fp,
        )
