"""Typed schemas for D3 Ollama hypothesis testing and step actions."""

from typing import Literal

from pydantic import Field

from selfheal.models import StrictModel


class ModelToolCall(StrictModel):
    """Structured tool request from the model."""

    tool: str = Field(min_length=1, max_length=64)
    params: dict[str, object] = Field(default_factory=dict)


class ModelHypothesisStep(StrictModel):
    """One step in the bounded hypothesis testing loop."""

    thought: str = Field(min_length=1, max_length=1024)
    action: Literal["tool_call", "conclude", "abstain"]
    tool_call: ModelToolCall | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    root_service: str | None = Field(default=None, max_length=128)
    proposed_action: str | None = Field(default=None, max_length=64)
    proposed_params: dict[str, object] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2048)


class ModelDiagnosisResponse(StrictModel):
    """Final diagnosis conclusion from the model."""

    conclusion: Literal["root_cause_found", "abstain", "inconclusive"]
    root_service: str = Field(min_length=1, max_length=128)
    hypothesis: str = Field(min_length=1, max_length=512)
    confidence: float = Field(ge=0.0, le=1.0)
    proposed_action: str | None = Field(default=None, max_length=64)
    proposed_params: dict[str, object] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2048)
