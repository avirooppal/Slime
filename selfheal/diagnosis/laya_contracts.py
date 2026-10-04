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


class LayaAblationReport(StrictModel):
    """Feature ablation measurement evaluating classifier robustness under signal dropout."""

    ablated_feature: str
    baseline_accuracy: float = Field(ge=0.0, le=1.0)
    ablated_accuracy: float = Field(ge=0.0, le=1.0)
    accuracy_delta: float
    importance_rank: int = 1
