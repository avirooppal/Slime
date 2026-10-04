"""Pure typed ranking function: similar-context proven success * confidence / blast radius."""

from dataclasses import dataclass

from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult
from selfheal.remediation.registry import ActionRegistry
from selfheal.safety.contracts import Proposal, Risk, Snapshot
from selfheal.safety.inventory import Inventory


@dataclass(frozen=True)
class RankedProposal:
    """A scored, policy-ready action proposal."""

    proposal: Proposal
    score: float
    candidate: CandidateCause
    reason: str


class Planner:
    """Pure, typed ranking function over candidate root causes and registered actions."""

    def __init__(self, registry: ActionRegistry, inventory: Inventory) -> None:
        """Initialize with action registry and inventory reader."""
        self.registry = registry
        self.inventory = inventory

    def plan(
        self,
        diagnosis: DiagnosisResult,
        historical_success_weights: dict[str, float] | None = None,
    ) -> list[RankedProposal]:
        """Rank candidate actions.

        Formula:
            proven_success_weight * confidence / blast_radius
        with preference for least-invasive root-cause actions.
        Rejects unregistered actions, invalid parameters, or unknown targets.
        """
        if diagnosis.status != "valid" or not diagnosis.candidates:
            return []

        weights = historical_success_weights or {}
        ranked: list[RankedProposal] = []

        for candidate in diagnosis.candidates:
            if not candidate.proposed_action or not candidate.proposed_params:
                continue

            # Verify action is registered
            try:
                action = self.registry.get(candidate.proposed_action)
            except LookupError:
                continue

            if action.risk == Risk.FORBIDDEN:
                continue

            # Verify parameters validate against the action's schema
            try:
                params = action.schema.model_validate(candidate.proposed_params)
            except Exception:  # noqa: BLE001, S112
                continue

            # Check target in inventory
            try:
                snapshot: Snapshot = self.inventory.snapshot(params.target)
            except Exception:  # noqa: BLE001, S112
                continue

            # Target kind compatibility
            if not snapshot or snapshot.kind not in action.target_kinds:
                continue

            # Blast radius
            blast_radius = max(action.blast_radius, snapshot.blast_radius, candidate.blast_radius, 1)

            # Historical success weight (defaults to 1.0; 1.5 if historically proven successful)
            proven_success = weights.get(f"{candidate.proposed_action}:{params.target}", 1.0)

            # Ranking score: proven_success * confidence / blast_radius
            score = (proven_success * candidate.confidence) / blast_radius

            proposal = Proposal(
                incident_id=diagnosis.incident_id,
                name=candidate.proposed_action,
                params=params.model_dump(mode="json"),
                expected_revision=snapshot.revision,
                confidence=round(candidate.confidence, 3),
            )

            ranked.append(
                RankedProposal(
                    proposal=proposal,
                    score=round(score, 4),
                    candidate=candidate,
                    reason=f"Confidence {candidate.confidence:.2f}, blast radius {blast_radius}, success weight {proven_success:.2f}",
                )
            )

        # Sort descending by score
        ranked.sort(key=lambda r: r.score, reverse=True)
        return ranked
