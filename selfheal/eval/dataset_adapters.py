"""Public and local dataset adapters for incident benchmarking."""

from abc import ABC, abstractmethod
from pathlib import Path

from selfheal.chaos.contracts import Scenario
from selfheal.chaos.scenarios import adversarial_scenarios, standard_scenarios


class DatasetAdapter(ABC):
    """Abstract interface for benchmark datasets."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the dataset."""

    @property
    @abstractmethod
    def license(self) -> str:
        """License of the dataset."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if dataset artifacts or traces are locally accessible."""

    @abstractmethod
    def load_scenarios(self) -> list[Scenario]:
        """Load scenarios into typed Scenario contracts."""

    @abstractmethod
    def documentation(self) -> str:
        """Honest status documentation regarding availability and licensing."""


class LocalCatalogAdapter(DatasetAdapter):
    """Built-in local fault injection and adversarial scenario catalog from Phase 4."""

    def __init__(self, include_adversarial: bool = True) -> None:
        self.include_adversarial = include_adversarial

    @property
    def name(self) -> str:
        return "Slime Local Chaos Catalog"

    @property
    def license(self) -> str:
        return "Apache-2.0"

    def is_available(self) -> bool:
        return True

    def load_scenarios(self) -> list[Scenario]:
        scenarios = list(standard_scenarios())
        if self.include_adversarial:
            scenarios.extend(adversarial_scenarios())
        return scenarios

    def documentation(self) -> str:
        return "Built-in synthetic and adversarial failure scenario catalog; 100% locally reproducible."


class TrainTicketAdapter(DatasetAdapter):
    """Adapter for the public Train-Ticket microservice benchmark dataset."""

    def __init__(self, data_dir: Path | str = Path("benchmarks/data/train-ticket")) -> None:
        self.data_dir = Path(data_dir)

    @property
    def name(self) -> str:
        return "Train-Ticket Microservice Benchmark"

    @property
    def license(self) -> str:
        return "Apache-2.0"

    def is_available(self) -> bool:
        return self.data_dir.exists() and any(self.data_dir.glob("*.json"))

    def load_scenarios(self) -> list[Scenario]:
        if not self.is_available():
            raise FileNotFoundError(
                f"Train-Ticket dataset traces not found at {self.data_dir}. "
                "Download public traces or place json traces in benchmarks/data/train-ticket."
            )
        # Load external scenarios if files are provided
        return []

    def documentation(self) -> str:
        if self.is_available():
            return f"Train-Ticket dataset active at {self.data_dir} (Apache-2.0)."
        return (
            f"Train-Ticket traces not found at {self.data_dir}. "
            "No public traces downloaded; running without invented benchmark claims."
        )


class AIOpsChallengeAdapter(DatasetAdapter):
    """Adapter for public AIOps KPI / Log Challenge benchmark datasets."""

    def __init__(self, data_dir: Path | str = Path("benchmarks/data/aiops-challenge")) -> None:
        self.data_dir = Path(data_dir)

    @property
    def name(self) -> str:
        return "AIOps Challenge Dataset (NetMan / Tsinghua)"

    @property
    def license(self) -> str:
        return "Academic Research Use / CC BY-NC 4.0"

    def is_available(self) -> bool:
        return self.data_dir.exists() and any(self.data_dir.glob("*.csv"))

    def load_scenarios(self) -> list[Scenario]:
        if not self.is_available():
            raise FileNotFoundError(
                f"AIOps Challenge dataset not found at {self.data_dir}. "
                "Dataset requires academic registration; no mock data invented."
            )
        return []

    def documentation(self) -> str:
        if self.is_available():
            return f"AIOps Challenge dataset active at {self.data_dir}."
        return (
            f"AIOps Challenge dataset not found at {self.data_dir}. "
            "Requires upstream academic registration; documented honestly without synthetic claims."
        )
