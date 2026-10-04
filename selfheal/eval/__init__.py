"""Evaluation and reproducible benchmarking for Slime."""

from selfheal.eval.contracts import BenchmarkReport, TierMetrics
from selfheal.eval.dataset_adapters import (
    AIOpsChallengeAdapter,
    DatasetAdapter,
    LocalCatalogAdapter,
    TrainTicketAdapter,
)
from selfheal.eval.runner import BenchmarkRunner

__all__ = [
    "AIOpsChallengeAdapter",
    "BenchmarkReport",
    "BenchmarkRunner",
    "DatasetAdapter",
    "LocalCatalogAdapter",
    "TierMetrics",
    "TrainTicketAdapter",
]
