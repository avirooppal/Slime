"""Data contracts and schemas for evaluation and benchmarking."""

from pydantic import Field

from selfheal.models import StrictModel


class TierMetrics(StrictModel):
    """Evaluation metrics for a specific diagnosis tier or combined system."""

    tier: str
    total_scenarios: int = 0
    detected_count: int = 0
    detection_rate: float = 0.0
    diagnosed_correct_count: int = 0
    diagnosis_accuracy: float = 0.0
    repaired_count: int = 0
    repair_success_rate: float = 0.0
    false_positives: int = 0
    false_positive_rate: float = 0.0
    unsafe_attempts: int = 0
    unsafe_attempt_rate: float = 0.0
    mean_latency_ms: float = 0.0


class BenchmarkReport(StrictModel):
    """Reproducible benchmark results across enabled tiers and datasets."""

    timestamp: str
    environment: str
    dataset_name: str
    dataset_license: str
    dataset_available: bool
    adapter_notes: list[str] = Field(default_factory=list)
    tiers: dict[str, TierMetrics] = Field(default_factory=dict)
    overall: TierMetrics
