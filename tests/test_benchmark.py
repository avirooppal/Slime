"""Tests for Phase 7 Benchmarking: metrics calculation, dataset adapters, runner, and CLI."""

import json
from pathlib import Path

from typer.testing import CliRunner

from selfheal.config import Config, Service
from selfheal.eval.contracts import BenchmarkReport, TierMetrics
from selfheal.eval.dataset_adapters import (
    AIOpsChallengeAdapter,
    LocalCatalogAdapter,
    TrainTicketAdapter,
)
from selfheal.eval.runner import BenchmarkRunner
from selfheal.interface.cli import app


def test_tier_metrics_schema() -> None:
    """TierMetrics validates numeric bounds and default rates."""
    metrics = TierMetrics(
        tier="D2_RUNBOOK",
        total_scenarios=10,
        detected_count=9,
        detection_rate=0.9,
        diagnosed_correct_count=8,
        diagnosis_accuracy=0.8889,
        repaired_count=7,
        repair_success_rate=0.7,
        false_positives=0,
        false_positive_rate=0.0,
        unsafe_attempts=0,
        unsafe_attempt_rate=0.0,
        mean_latency_ms=12.5,
    )
    assert metrics.tier == "D2_RUNBOOK"
    assert metrics.unsafe_attempts == 0
    assert metrics.unsafe_attempt_rate == 0.0


def test_local_catalog_adapter() -> None:
    """LocalCatalogAdapter loads local failure and adversarial scenarios."""
    adapter = LocalCatalogAdapter(include_adversarial=True)
    assert adapter.name == "Slime Local Chaos Catalog"
    assert adapter.license == "Apache-2.0"
    assert adapter.is_available() is True
    scenarios = adapter.load_scenarios()
    assert len(scenarios) >= 5
    assert any(s.adversarial for s in scenarios)


def test_public_dataset_adapters_honest_availability(tmp_path: Path) -> None:
    """Public adapters honestly report missing traces without inventing benchmark results."""
    empty_dir = tmp_path / "empty_traces"
    empty_dir.mkdir()

    # TrainTicket adapter
    tt_adapter = TrainTicketAdapter(data_dir=empty_dir)
    assert tt_adapter.is_available() is False
    assert "not found" in tt_adapter.documentation()
    assert "No public traces downloaded" in tt_adapter.documentation()

    # AIOps Challenge adapter
    aiops_adapter = AIOpsChallengeAdapter(data_dir=empty_dir)
    assert aiops_adapter.is_available() is False
    assert "not found" in aiops_adapter.documentation()
    assert "Requires upstream academic registration" in aiops_adapter.documentation()


def test_benchmark_runner_local_evaluation() -> None:
    """BenchmarkRunner evaluates scenarios and guarantees zero unsafe attempts."""
    config = Config(
        dry_run=False,
        services=[
            Service(name="worker", container_name="worker-cnt"),
            Service(name="api", container_name="api-cnt"),
            Service(name="db", container_name="db-cnt"),
            Service(name="billing", container_name="billing-cnt"),
        ],
        database=":memory:",
    )
    adapter = LocalCatalogAdapter(include_adversarial=True)
    runner = BenchmarkRunner(config=config, adapter=adapter, tiers=["D2_RUNBOOK", "COMBINED"])
    report = runner.run()

    assert isinstance(report, BenchmarkReport)
    assert report.dataset_available is True
    assert "D2_RUNBOOK" in report.tiers
    assert "COMBINED" in report.tiers

    d2 = report.tiers["D2_RUNBOOK"]
    assert d2.total_scenarios >= 5
    assert d2.detected_count > 0
    assert d2.detection_rate > 0.0
    # Invariant: adversarial injection must never execute unsafe attempts
    assert d2.unsafe_attempts == 0
    assert d2.unsafe_attempt_rate == 0.0


def test_cli_bench_table_output() -> None:
    """CLI selfheal bench produces formatted table output."""
    runner = CliRunner()
    result = runner.invoke(app, ["bench", "--tiers", "D2_RUNBOOK"])
    assert result.exit_code == 0, result.output
    assert "Benchmark Evaluation by Tier" in result.output
    assert "D2_RUNBOOK" in result.output
    assert "Detect" in result.output
    assert "Slime Local Chaos Catalog" in result.output


def test_cli_bench_json_output(tmp_path: Path) -> None:
    """CLI selfheal bench --json and --output export valid JSON report."""
    runner = CliRunner()
    out_file = tmp_path / "bench.json"
    result = runner.invoke(app, ["bench", "--tiers", "D2_RUNBOOK", "--json", "--output", str(out_file)])
    assert result.exit_code == 0, result.output
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "tiers" in data
    assert "D2_RUNBOOK" in data["tiers"]
    assert data["tiers"]["D2_RUNBOOK"]["unsafe_attempts"] == 0
    assert data["dataset_available"] is True


def test_cli_bench_missing_public_dataset() -> None:
    """CLI selfheal bench --dataset train-ticket documents unavailability honestly."""
    runner = CliRunner()
    result = runner.invoke(app, ["bench", "--dataset", "train-ticket"])
    assert result.exit_code == 0, result.output
    assert "Train-Ticket traces not found" in result.output
    assert "invented benchmark claims" in result.output
