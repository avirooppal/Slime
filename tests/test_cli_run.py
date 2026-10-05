"""CLI polling behavior for continuous local monitoring."""

from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from selfheal.config import Config
from selfheal.interface import cli


def test_run_continuous_by_default_and_once_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The normal command polls with delay; --once performs exactly one cycle."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        yaml.safe_dump(Config(database=str(tmp_path / "state.db"), poll_seconds=0.25)
                       .model_dump(mode="json")), encoding="utf-8"
    )
    calls: list[str] = []
    sleeps: list[float] = []

    class FakeCoordinator:
        """Minimal test coordinator that stops a continuous run after two polls."""

        def __init__(self, _config: Config) -> None:
            """Record construction without starting collectors."""
            calls.append("init")

        def step(self) -> list[object]:
            """Return no incidents and then simulate an operator interrupt."""
            calls.append("step")
            if calls.count("step") == 3:
                raise KeyboardInterrupt
            return []

        def close(self) -> None:
            """Record shutdown of the coordinator."""
            calls.append("close")

    monkeypatch.setattr(cli, "Coordinator", FakeCoordinator)
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)
    runner = CliRunner()
    continuous = runner.invoke(cli.app, ["run", "--config", str(config_file)])
    assert continuous.exit_code == 0
    assert calls == ["init", "step", "step", "step", "close"]
    assert sleeps == [0.25, 0.25]
    assert "Monitoring stopped by operator" in continuous.output

    calls.clear()
    sleeps.clear()
    one_cycle = runner.invoke(cli.app, ["run", "--config", str(config_file), "--once"])
    assert one_cycle.exit_code == 0
    assert calls == ["init", "step", "close"]
    assert sleeps == []
