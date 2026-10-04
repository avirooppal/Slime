"""Notification contracts and types for Slime Phase 9."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from selfheal.models import utcnow


class NotificationLevel(str, Enum):
    """Urgency level of the notification."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class NotificationEvent(BaseModel):
    """Structured notification event payload."""

    event_type: str = Field(description="Event kind: incident_detected, approval_required, repair_executed, etc.")
    title: str = Field(description="Short human-readable title.")
    message: str = Field(description="Descriptive message content.")
    level: NotificationLevel = Field(default=NotificationLevel.INFO)
    timestamp: str = Field(default_factory=lambda: utcnow().isoformat())
    metadata: dict[str, Any] = Field(default_factory=dict)
