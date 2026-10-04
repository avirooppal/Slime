"""Data contracts and budget constraints for opt-in Cloud LLM (D4)."""

from pydantic import Field

from selfheal.models import StrictModel


class CloudBudget(StrictModel):
    """Hourly call and spend cap limits for cloud diagnosis."""

    max_calls_per_hour: int = Field(default=10, ge=1)
    max_spend_usd: float = Field(default=5.0, ge=0.1)
    calls_this_hour: int = 0
    estimated_spend_usd: float = 0.0
    hour_bucket: str = ""

    def can_call(self, current_hour_bucket: str) -> tuple[bool, str]:
        """Check if call budget and spend caps allow an API call."""
        if self.hour_bucket != current_hour_bucket:
            # New hour bucket: reset hourly counters
            self.hour_bucket = current_hour_bucket
            self.calls_this_hour = 0
        if self.calls_this_hour >= self.max_calls_per_hour:
            return (False, f"Cloud call cap reached ({self.calls_this_hour}/{self.max_calls_per_hour} calls/hr)")
        if self.estimated_spend_usd >= self.max_spend_usd:
            return (False, f"Cloud spend cap reached (${self.estimated_spend_usd:.2f}/${self.max_spend_usd:.2f})")
        return (True, "Budget permitted")

    def record_call(self, estimated_cost: float = 0.02) -> None:
        """Record an executed call and its estimated cost."""
        self.calls_this_hour += 1
        self.estimated_spend_usd += estimated_cost


class CloudSummaryRequest(StrictModel):
    """Sanitized, summary-only payload sent to cloud models. Secrets are strictly omitted."""

    incident_id: str
    target_services: list[str]
    root_candidates: list[str]
    downstream: list[str]
    template_ids: list[str]
    metric_signatures: list[str]
    change_signatures: list[str]
    redacted_evidence_summary: str


class CloudDiagnosisResponse(StrictModel):
    """Validated structured response from cloud models."""

    hypothesis: str
    target_service: str
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_action: str
    proposed_target: str
    rationale: str
    blast_radius: int = Field(default=1, ge=1)
