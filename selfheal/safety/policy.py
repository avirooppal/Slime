"""Deterministic safety gate with no model, shell, or remediation heuristics."""

import sqlite3

from pydantic import ValidationError

from selfheal.diagnosis.limits import BoundedRead
from selfheal.remediation.contracts import Action, ActionBackend, TargetParams
from selfheal.remediation.registry import ActionRegistry
from selfheal.safety.contracts import (
    Decision,
    DiagnosisContext,
    Proposal,
    Risk,
    SafetySettings,
    Snapshot,
)
from selfheal.safety.inventory import Inventory
from selfheal.safety.state import SafetyState


class Policy:
    """Validate untrusted suggestions and serialize final execution reservations."""

    def __init__(
        self,
        registry: ActionRegistry,
        inventory: Inventory,
        backend: ActionBackend,
        state: SafetyState,
        settings: SafetySettings,
        dry_run: bool = True,
        max_auto_targets: int = 1,
    ) -> None:
        """Wire trusted dependencies; dry-run is enabled unless explicitly disabled."""
        self.registry, self.inventory, self.backend, self.state = (
            registry,
            inventory,
            backend,
            state,
        )
        self.settings, self.dry_run, self.max_auto_targets = settings, dry_run, max_auto_targets
        self.reader = BoundedRead()

    def live_snapshot(self, target: str) -> Snapshot:
        """Bound the read-only live probe before authorizing any mutation."""
        return self.reader.call(lambda: self.inventory.snapshot(target), 3, self.state.stop.is_set)

    def preconditions(self, action: Action, snapshot: Snapshot, params: TargetParams) -> bool:
        """Bound read-only adapter eligibility checks; never execute actions in a worker."""
        return self.reader.call(
            lambda: action.preconditions(snapshot, params, self.backend), 3, self.state.stop.is_set
        )

    def _check(self, raw: object, context: DiagnosisContext) -> Decision:
        """Return the first deterministic rejecting rule, after a fresh live probe."""

        def refuse(rule: str, human: bool = False) -> Decision:
            """Provide a bounded reason without echoing untrusted raw input."""
            return Decision(False, rule, human)

        try:
            proposal = Proposal.model_validate(raw).model_copy(deep=True)
        except (ValidationError, ValueError, TypeError):
            return refuse("invalid_proposal")
        if context.incident_id is not None and proposal.incident_id != context.incident_id:
            return refuse("incident_mismatch", True)
        try:
            action = self.registry.get(proposal.name)
        except LookupError:
            return refuse("unknown_action")
        if action.risk == Risk.FORBIDDEN:
            return refuse("forbidden_action")
        try:
            params = action.schema.model_validate(proposal.params)
        except (ValidationError, ValueError, TypeError):
            return refuse("invalid_parameters")
        if context.status != "valid":
            return refuse("unreliable_diagnosis", True)
        if context.budget_exhausted:
            return refuse("budget_exhausted", True)
        if context.flapping:
            return refuse("flapping_incident", True)
        if proposal.confidence < self.settings.minimum_confidence:
            return refuse("low_confidence", True)
        if self.state.killed():
            return refuse("kill_switch")
        if self.state.circuit_open():
            return refuse("circuit_breaker", True)
        try:
            snapshot = self.live_snapshot(params.target)
        except InterruptedError:
            return refuse("kill_switch")
        except LookupError:
            return refuse("unknown_target")
        except Exception:  # noqa: BLE001 - unknown adapter failures must fail closed
            return refuse("inventory_unavailable", True)
        if snapshot.target != params.target or snapshot.kind not in action.target_kinds:
            return refuse("target_kind_mismatch")
        if snapshot.revision != proposal.expected_revision:
            return refuse("state_changed_rediagnose", True)
        approved = self.state.approved(proposal)
        needs_approval = action.risk == Risk.APPROVAL or snapshot.critical
        if needs_approval and not approved:
            return refuse(
                "critical_approval_required" if snapshot.critical else "approval_required", True
            )
        radius = max(action.blast_radius, snapshot.blast_radius)
        if radius < 1 or (not needs_approval and radius > self.max_auto_targets):
            return refuse("blast_radius", True)
        if self.dry_run:
            return refuse("dry_run")
        if self.state.cooling_down(
            action.name, params.target, max(action.cooldown_seconds, self.settings.cooldown_seconds)
        ):
            return refuse("cooldown")
        if not needs_approval and self.state.recent_count() >= self.settings.max_auto_per_hour:
            return refuse("hourly_limit", True)
        try:
            if not self.preconditions(action, snapshot, params):
                return refuse("preconditions_failed", True)
        except InterruptedError:
            return refuse("kill_switch")
        except Exception:  # noqa: BLE001 - unknown adapter failures must fail closed
            return refuse("preconditions_unavailable", True)
        return Decision(True, "authorized", proposal=proposal, snapshot=snapshot)

    def evaluate(self, raw: object, context: DiagnosisContext | None = None) -> Decision:
        """Audit an advisory decision; this never creates execution authority."""
        try:
            with self.state.transaction():
                decision = self._check(raw, context or DiagnosisContext())
                self.state.store.audit("policy", decision.rule, "advisory decision")
            return decision
        except sqlite3.Error:
            return Decision(False, "audit_or_state_unavailable", True)

    def authorize(self, raw: object, context: DiagnosisContext | None = None) -> Decision:
        """Recheck and reserve under a SQLite write lock immediately before dispatch."""
        try:
            with self.state.transaction():
                decision = self._check(raw, context or DiagnosisContext())
                self.state.store.audit("policy", decision.rule, "final authorization decision")
                if not decision.allowed:
                    return decision
                assert decision.proposal is not None and decision.snapshot is not None
                action = self.registry.get(decision.proposal.name)
                automatic = action.risk == Risk.SAFE and not decision.snapshot.critical
                action_id = self.state.reserve(
                    decision.proposal, decision.snapshot.target, automatic
                )
                return Decision(
                    True,
                    decision.rule,
                    proposal=decision.proposal,
                    snapshot=decision.snapshot,
                    action_id=action_id,
                )
        except sqlite3.Error:
            return Decision(False, "audit_or_state_unavailable", True)
