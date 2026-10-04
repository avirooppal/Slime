"""One authorized execution, one stability verification, at most one safe rollback."""

import warnings
from dataclasses import dataclass, replace

from selfheal.correlator.engine import Correlator
from selfheal.models import Incident, State
from selfheal.remediation.contracts import Receipt
from selfheal.safety.contracts import Decision, DiagnosisContext
from selfheal.safety.policy import Policy
from selfheal.verifier.stability import StabilityVerifier, Verification


@dataclass(frozen=True)
class ExecutionResult:
    """Explicit execution outcome for CLI, learning and later postmortems."""

    status: str
    rule: str
    decision: Decision
    verification: Verification | None = None
    rolled_back: bool = False


class Executor:
    """The only coordinator allowed to dispatch registered typed actions."""

    def __init__(
        self, policy: Policy, verifier: StabilityVerifier, correlator: Correlator | None = None
    ) -> None:
        """Keep lifecycle integration optional for isolated unit tests."""
        self.policy, self.verifier, self.correlator = policy, verifier, correlator

    def _transition(self, incident: Incident | None, state: State, reason: str) -> None:
        """Persist and audit lifecycle state using the correlator's legal edges."""
        if incident is not None and self.correlator is not None:
            previous_state, previous_time = incident.state, incident.updated_at
            try:
                with self.policy.state.store.connection:
                    self.correlator.transition(incident, state, reason)
            except Exception:
                incident.state, incident.updated_at = previous_state, previous_time
                raise

    def run(
        self,
        raw: object,
        context: DiagnosisContext | None = None,
        incident: Incident | None = None,
    ) -> ExecutionResult:
        """Reauthorize live state; refuse unreliable outputs and never retry failed fixes."""
        context = context or DiagnosisContext()
        if self.verifier.timeout < self.verifier.window:
            raise ValueError("verification budget cannot cover stability")
        if incident is not None and (
            self.correlator is None or incident.state != State.INVESTIGATING
        ):
            raise ValueError("an attached incident must be investigating")
        if incident is not None and incident.flap_count:
            context = replace(context, flapping=True)
        if incident is not None:
            context = replace(context, incident_id=incident.id)
        decision = self.policy.authorize(raw, context)
        if not decision.allowed:
            if decision.needs_human:
                self._transition(incident, State.ESCALATED, decision.rule)
            return ExecutionResult("refused", decision.rule, decision)
        assert (
            decision.proposal is not None
            and decision.snapshot is not None
            and decision.action_id is not None
        )
        proposal, snapshot, action_id = decision.proposal, decision.snapshot, decision.action_id
        action = self.policy.registry.get(proposal.name)
        params = action.schema.model_validate(proposal.params)
        state = self.policy.state
        receipt: Receipt | None = None
        verification: Verification | None = None
        recovered = False
        failure = "execution_failed"
        try:
            live = self.policy.live_snapshot(params.target)
            if live != snapshot:
                failure = "state_changed_rediagnose"
                raise RuntimeError("target changed after reservation")
            if state.killed():
                failure = "kill_switch"
                raise RuntimeError("operator stopped actions")
            if not self.policy.preconditions(action, live, params):
                failure = "preconditions_changed"
                raise RuntimeError("preconditions changed")
            self._transition(incident, State.MITIGATING, "deterministic safety policy authorized")
            state.status(action_id, "executing")
            if state.killed():
                failure = "kill_switch"
                raise RuntimeError("operator stopped before dispatch")
            receipt = action.execute(live, params, self.policy.backend, state.killed)
            state.save_receipt(action_id, receipt)
            state.status(action_id, "verifying")
            self._transition(
                incident, State.VERIFYING, "typed action completed; checking stability"
            )
            verification = self.verifier.verify(
                lambda: action.verify(snapshot, params, self.policy.backend), state.killed
            )
            if verification.stable:
                recovered = True
                state.finish(action_id, True, self.policy.settings.failure_limit)
                self._transition(incident, State.RESOLVED, "full stability window passed")
                return ExecutionResult("success", verification.reason, decision, verification)
            failure = verification.reason
        except Exception:  # noqa: BLE001 - any adapter failure must stop remediation
            if recovered:
                # Reporting failure is not a failed repair: never undo verified recovery.
                state.stop.set()
                try:
                    state.kill_switch(True, "executor: reporting_failure")
                except Exception:  # noqa: BLE001 - broken persistence still leaves the stop event set
                    warnings.warn(
                        "Safety persistence failed; in-process kill switch remains active",
                        stacklevel=2,
                    )
                return ExecutionResult("escalated", "reporting_failure", decision, verification)
            if state.killed():
                failure = "kill_switch"
            with state.store.connection:
                state.store.audit(
                    action_id, failure, "bounded execution failure; no automatic retry"
                )
        rolled_back = False
        if receipt is not None and not state.killed():
            try:
                rolled_back = action.rollback(snapshot, receipt, self.policy.backend, state.killed)
            except Exception:  # noqa: BLE001 - any adapter failure must stop remediation
                rolled_back = False
            with state.store.connection:
                state.store.audit(
                    action_id,
                    "rollback_completed" if rolled_back else "rollback_unavailable",
                    "restoration attempted once; escalate",
                )
        state.finish(action_id, False, self.policy.settings.failure_limit)
        self._transition(incident, State.ESCALATED, failure)
        return ExecutionResult("escalated", failure, decision, verification, rolled_back)
