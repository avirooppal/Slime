"""Contracts and data structures for learned incident fingerprints and shortcuts."""

import hashlib
import json

from pydantic import Field

from selfheal.diagnosis.contracts import CandidateCause
from selfheal.models import StrictModel


def _jaccard(a: set[str], b: set[str]) -> float:
    """Compute Jaccard similarity between two sets of strings."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union > 0 else 1.0


class ContextFingerprint(StrictModel):
    """Canonical representation of incident context across topology, symptoms, and metrics."""

    primary_service: str
    services: list[str] = Field(default_factory=list)
    root_candidates: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)
    template_ids: list[str] = Field(default_factory=list)
    metric_signatures: list[str] = Field(default_factory=list)
    change_signatures: list[str] = Field(default_factory=list)
    event_kinds: list[str] = Field(default_factory=list)
    fingerprint_hash: str = ""

    def model_post_init(self, context: object) -> None:
        """Compute deterministic hash if not set."""
        if not self.fingerprint_hash:
            canonical = json.dumps(
                {
                    "primary_service": self.primary_service,
                    "services": sorted(self.services),
                    "root_candidates": sorted(self.root_candidates),
                    "downstream": sorted(self.downstream),
                    "template_ids": sorted(self.template_ids),
                    "metric_signatures": sorted(self.metric_signatures),
                    "change_signatures": sorted(self.change_signatures),
                    "event_kinds": sorted(self.event_kinds),
                },
                sort_keys=True,
            )
            self.fingerprint_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def similarity(self, other: "ContextFingerprint") -> float:
        """Compute weighted multi-attribute similarity between 0.0 and 1.0."""
        # 1. Services & topology (weight 0.35)
        svc_j = _jaccard(set(self.services), set(other.services))
        root_j = _jaccard(set(self.root_candidates), set(other.root_candidates))
        down_j = _jaccard(set(self.downstream), set(other.downstream))
        topo_score = 0.4 * svc_j + 0.4 * root_j + 0.2 * down_j

        # 2. Template IDs (Drain3) (weight 0.35)
        tpl_score = _jaccard(set(self.template_ids), set(other.template_ids))

        # 3. Metric signatures (weight 0.15)
        metric_score = _jaccard(set(self.metric_signatures), set(other.metric_signatures))

        # 4. Change signatures (weight 0.15)
        change_score = _jaccard(set(self.change_signatures), set(other.change_signatures))

        total = 0.35 * topo_score + 0.35 * tpl_score + 0.15 * metric_score + 0.15 * change_score
        return round(total, 4)

    def detect_shift(self, other: "ContextFingerprint") -> tuple[bool, list[str]]:
        """Detect context shift between this historical fingerprint and a new incident.

        Returns (is_shifted, list of reasons explaining the shift).
        """
        reasons: list[str] = []

        # 1. Root cause candidate mismatch
        if (
            self.root_candidates
            and other.root_candidates
            and not (set(self.root_candidates) & set(other.root_candidates))
        ):
            reasons.append(
                f"root candidate mismatch: historical {self.root_candidates} vs current {other.root_candidates}"
            )

        # 2. Primary service mismatch
        if self.primary_service != other.primary_service:
            reasons.append(
                f"primary service mismatch: historical {self.primary_service} vs current {other.primary_service}"
            )

        # 3. Conflicting metric signatures (e.g. disk full vs cpu pressure)
        if (
            self.metric_signatures
            and other.metric_signatures
            and not (set(self.metric_signatures) & set(other.metric_signatures))
        ):
            reasons.append(
                f"conflicting metric patterns: historical {self.metric_signatures} vs current {other.metric_signatures}"
            )

        # 4. Severe template divergence
        if self.template_ids and other.template_ids:
            tpl_sim = _jaccard(set(self.template_ids), set(other.template_ids))
            if tpl_sim < 0.34:
                reasons.append(
                    f"template divergence: overlap ratio {tpl_sim:.2f} < 0.34"
                )

        # 5. Change signature mismatch
        if (self.change_signatures or other.change_signatures) and not (
            set(self.change_signatures) & set(other.change_signatures)
        ):
            # One had a deployment/config change and the other did not or had a different change
            reasons.append(
                f"change context shift: historical {self.change_signatures} vs current {other.change_signatures}"
            )

        return (len(reasons) > 0, reasons)


class LearningConfig(StrictModel):
    """Configuration for historical fix learning and shortcut safety gates."""

    min_samples: int = Field(default=2, ge=1)
    similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    enabled: bool = True


class ShortcutDecision(StrictModel):
    """Decision on whether historical verified fixes can safely shorten diagnosis."""

    eligible: bool
    shortened: bool
    candidate: CandidateCause | None = None
    sample_count: int = 0
    failed_count: int = 0
    best_similarity: float = 0.0
    shift_detected: bool = False
    reasons: list[str] = Field(default_factory=list)
    fingerprint: ContextFingerprint
