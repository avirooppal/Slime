"""Data contracts and ablation schemas for opt-in Laya classifier (D5)."""

from pydantic import Field

from selfheal.models import StrictModel


class LayaPrediction(StrictModel):
    """Calibrated closed-set root-cause prediction from Laya model."""

    predicted_class: str
    target_service: str
    raw_probability: float = Field(ge=0.0, le=1.0)
    calibrated_confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: float = Field(ge=0.0)
    brier_score: float = 0.0
    proposed_action: str | None = None


class LayaAblationReport(StrictModel):
    """Feature ablation measurement evaluating classifier robustness under signal dropout."""

    ablated_feature: str
    baseline_accuracy: float = Field(ge=0.0, le=1.0)
    ablated_accuracy: float = Field(ge=0.0, le=1.0)
    accuracy_delta: float
    importance_rank: int = 1


class LayaEvaluationReport(StrictModel):
    """Held-out comparison required before Laya may shorten diagnosis."""

    model: str
    dataset_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    held_out_count: int = Field(ge=20)
    accuracy: float = Field(ge=0.0, le=1.0)
    baseline_accuracy: float = Field(ge=0.0, le=1.0)
    ece: float = Field(ge=0.0, le=1.0)
    baseline_ece: float = Field(ge=0.0, le=1.0)
    median_latency_ms: float = Field(ge=0.0)
    baseline_median_latency_ms: float = Field(ge=0.0)
