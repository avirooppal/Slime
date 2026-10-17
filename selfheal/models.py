"""Validated signal and incident contracts; timestamps are always UTC."""

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utcnow() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Reject unexpected fields at every configuration and data boundary."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Kind(str, Enum):
    """Normalized signal categories."""

    LOG = "log"
    METRIC = "metric"
    HEALTH = "health"
    CHANGE = "change"
    ALERT = "alert"


class State(str, Enum):
    """Incident lifecycle states."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


class Event(StrictModel):
    """One bounded, redacted signal from a collector or detector."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utcnow)
    kind: Kind
    service: str = Field(min_length=1, max_length=128)
    source: str = Field(max_length=1024)
    severity: str = "info"
    evidence: str = Field(default="", max_length=4096)
    template_id: str | None = None
    attributes: dict[str, bool | int | float | str | None] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        """Reject ambiguous timestamps and normalize timezone."""
        if value.tzinfo is None:
            raise ValueError("timestamp must have a timezone")
        return value.astimezone(timezone.utc)


class Incident(StrictModel):
    """Correlated evidence with explainable root candidate ordering."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    state: State = State.OPEN
    opened_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    services: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    root_candidates: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    flap_count: int = 0
