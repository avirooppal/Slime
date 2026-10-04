"""Closed immutable registry; risk is trusted metadata, never model output."""

from collections.abc import Iterable
from types import MappingProxyType

from selfheal.remediation.contracts import Action, RollbackImageParams, TargetParams
from selfheal.safety.contracts import Risk


class ActionRegistry:
    """Resolve known names and reject duplicate registration."""

    def __init__(self, actions: Iterable[Action]) -> None:
        """Freeze independent typed definitions for policy and executor reuse."""
        items = list(actions)
        mapping = {a.name: a for a in items}
        if len(mapping) != len(items):
            raise ValueError("duplicate action registration")
        self.actions = MappingProxyType(mapping)

    def get(self, name: str) -> Action:
        """Return a registered action; arbitrary names never dispatch."""
        try:
            return self.actions[name]
        except KeyError:
            raise LookupError("unknown action") from None


def default_registry() -> ActionRegistry:
    """Declare all nine requested actions with conservative approved risk tiers."""
    definitions = [
        ("restart_container", Risk.SAFE, "container"),
        ("restart_service", Risk.APPROVAL, "service"),
        ("clear_tmp_files", Risk.SAFE, "tmp_file"),
        ("rotate_logs", Risk.SAFE, "log_file"),
        ("kill_runaway_process", Risk.APPROVAL, "process"),
        ("free_docker_space", Risk.APPROVAL, "docker_image"),
        ("reload_nginx", Risk.APPROVAL, "service"),
        ("rerun_healthcheck", Risk.SAFE, "service"),
        ("rollback_to_previous_image", Risk.APPROVAL, "container"),
    ]
    return ActionRegistry(
        Action(
            name,
            RollbackImageParams if name == "rollback_to_previous_image" else TargetParams,
            risk,
            frozenset({kind}),
        )
        for name, risk, kind in definitions
    )
