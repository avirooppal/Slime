"""Typed chaos experiment scenarios and ground-truth execution contracts."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from selfheal.models import StrictModel


class FaultType(str, Enum):
    """Safe, non-destructive fault categories."""

    PROCESS_KILL = "process_kill"
    TEMP_FILE_FILL = "temp_file_fill"
    LOG_INJECTION = "log_injection"
    CONFIG_MUTATION = "config_mutation"
    HEALTH_PORT_HANG = "health_port_hang"
    ADVERSARIAL_INJECTION = "adversarial_injection"


class Scenario(StrictModel):
    """Ground truth experiment definition."""

    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    fault_type: FaultType
    target_service: str = Field(min_length=1, max_length=128)
    expected_root_cause: str = Field(min_length=1, max_length=256)
    expected_action: str | None = None
    adversarial: bool = False
    parameters: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class ExperimentOutcome:
    """End-to-end outcome of an executed chaos scenario."""

    scenario: Scenario
    timestamp: datetime
    detected: bool
    incident_id: str | None
    diagnosed_tier: str | None
    diagnosed_root: str | None
    planned_action: str | None
    policy_allowed: bool
    policy_rule: str
    executed: bool
    verified_stable: bool | None
    postmortem_generated: bool
    unsafe_action_prevented: bool
