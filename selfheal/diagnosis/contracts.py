"""Typed diagnosis contracts; coordinator sets DiagnosisContext, not diagnosis."""

from typing import Literal

from pydantic import Field

from selfheal.models import StrictModel


class DiagnosisTier(str):
    """Diagnosis sources in order of specificity and execution order."""

    D1_MEMORY = "D1_MEMORY"
    D2_RUNBOOK = "D2_RUNBOOK"
    D3_LOCAL_LLM = "D3_LOCAL_LLM"
    D4_CLOUD_LLM = "D4_CLOUD_LLM"
    D5_LAYA = "D5_LAYA"
    NONE = "NONE"


class CandidateCause(StrictModel):
    """Ranked root cause candidate with supporting evidence and proposed action."""

    hypothesis: str = Field(min_length=1, max_length=512)
    service: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    evidence_event_ids: list[str] = Field(default_factory=list)
    tier: str = Field(default=DiagnosisTier.NONE)
    proposed_action: str | None = Field(default=None, pattern=r"^[a-z_]{1,64}$")
    proposed_params: dict[str, object] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2048)
    blast_radius: int = Field(default=1, ge=1)


class DiagnosisResult(StrictModel):
    """Diagnosis tier outcome with explicit status and ranked candidates."""

    incident_id: str = Field(min_length=1, max_length=128)
    status: Literal["valid", "abstain", "invalid", "timeout"] = "valid"
    deciding_tier: str = Field(default=DiagnosisTier.NONE)
    candidates: list[CandidateCause] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def selected(self) -> CandidateCause | None:
        """Top candidate if status is valid and candidates exist."""
        if self.status == "valid" and self.candidates:
            return self.candidates[0]
        return None
