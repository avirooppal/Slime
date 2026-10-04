"""Strict untrusted proposals and trusted deterministic safety inputs."""

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from pydantic import ConfigDict, Field

from selfheal.models import StrictModel


class Risk(str, Enum):
    """Operator policy tiers; models cannot choose or override these."""

    SAFE = "SAFE"
    APPROVAL = "APPROVAL"
    FORBIDDEN = "FORBIDDEN"


class Proposal(StrictModel):
    """Untrusted action suggestion tied to the diagnosed inventory revision."""

    model_config = ConfigDict(
        extra="forbid", validate_assignment=True, revalidate_instances="always"
    )

    incident_id: str = Field(min_length=1, max_length=128)
    name: str = Field(pattern=r"^[a-z_]{1,64}$")
    params: dict[str, object]
    expected_revision: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)


@dataclass(frozen=True)
class DiagnosisContext:
    """Trusted orchestrator status, never taken from model/tool/log JSON."""

    status: Literal["valid", "invalid", "timeout", "abstain"] = "valid"
    flapping: bool = False
    budget_exhausted: bool = False
    incident_id: str | None = None


@dataclass(frozen=True)
class Snapshot:
    """Live target identity plus action-relevant revision, not display names alone."""

    target: str
    kind: str
    identity: str
    revision: str
    state: str
    healthy: bool
    critical: bool = False
    blast_radius: int = 1


@dataclass(frozen=True)
class Decision:
    """An auditable policy result; authorization is required separately."""

    allowed: bool
    rule: str
    needs_human: bool = False
    proposal: Proposal | None = None
    snapshot: Snapshot | None = None
    action_id: str | None = None


class SafetySettings(StrictModel):
    """Conservative limits explicitly approved by the operator for Phase 2."""

    minimum_confidence: float = Field(default=0.90, ge=0, le=1, allow_inf_nan=False)
    max_auto_per_hour: int = Field(default=5, ge=1, le=100, strict=True)
    cooldown_seconds: int = Field(default=300, ge=1, strict=True)
    failure_limit: int = Field(default=3, ge=1, strict=True)
    verification_interval_seconds: float = Field(default=5, gt=0, le=30)
    verification_timeout_seconds: float = Field(default=300, gt=0, allow_inf_nan=False)
