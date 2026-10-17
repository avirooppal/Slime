"""All registered lifecycle contracts remain policy-gated and independently testable."""

from dataclasses import replace

import pytest
from safety_fakes import Rig, proposal

from selfheal.remediation.executor import Executor
from selfheal.safety.contracts import Risk
from selfheal.verifier.stability import StabilityVerifier


@pytest.mark.parametrize(
    "name",
    [
        "restart_container",
        "restart_managed_process",
        "restart_service",
        "clear_tmp_files",
        "rotate_logs",
        "kill_runaway_process",
        "reload_nginx",
        "rollback_to_previous_image",
    ],
)
def test_each_typed_action_uses_same_gate_and_stability(rig: Rig, name: str) -> None:
    """Mock adapters prove every registry entry obeys identical authorization ordering."""
    policy, inventory, backend, clock = rig
    action = policy.registry.get(name)
    kind = next(iter(action.target_kinds))
    inventory.live = replace(inventory.live, target=kind + ".example", kind=kind)
    raw = proposal(inventory, name)
    if name == "rollback_to_previous_image":
        raw.params["previous_image"] = "sha256:" + "a" * 64
    if action.risk == Risk.APPROVAL:
        assert policy.evaluate(raw).rule == "approval_required"
        policy.state.approve(raw, "operator")
    result = Executor(policy, StabilityVerifier(clock=clock.monotonic, wait=clock.wait)).run(raw)
    assert result.status == "success" and result.verification.elapsed_seconds >= 120
    assert backend.executions == 1


def test_empty_verification_budget_rejected() -> None:
    """Do not permit an action plan with less verification time than its stability window."""
    with pytest.raises(ValueError):
        StabilityVerifier(window_seconds=120, timeout_seconds=119)
