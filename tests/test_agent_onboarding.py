"""First-run workflow integration and safe reuse of local operator settings."""

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from selfheal.config import load_config
from selfheal.interface import cli
from selfheal.interface.onboarding import prepare_agent


def test_agent_first_run_and_reuse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(cli, "run", lambda **kwargs: calls.append(kwargs))
    runner = CliRunner()
    first = runner.invoke(cli.app, ["agent", "--health", "http://localhost:8000/health",
                                   "--log", "app.log", "--once"])
    assert first.exit_code == 0, first.output
    config = tmp_path / ".slime/config.yaml"
    settings = load_config(config)
    assert settings.dry_run
    assert settings.services[0].logs == [str(tmp_path / "app.log")]
    assert settings.database == str(tmp_path / ".slime/slime.db")
    before = config.read_bytes()
    second = runner.invoke(cli.app, ["agent", "--once"])
    assert second.exit_code == 0, second.output
    assert config.read_bytes() == before
    assert len(calls) == 2 and all(c["once"] for c in calls)
    conflict = runner.invoke(cli.app, ["agent", "--health", "http://localhost:9000"])
    assert conflict.exit_code == 1
    assert config.read_bytes() == before
    assert len(calls) == 2
    renamed = runner.invoke(cli.app, ["agent", "--name", "other"])
    assert renamed.exit_code == 1
    assert config.read_bytes() == before


@pytest.mark.parametrize("options", [[], ["--arg", "worker.py"],
    ["--health", "file:///etc/passwd"], ["--health", "http://user:pass@localhost"],
    ["--health", "http://localhost:bad"], ["--health", "http://localhost/?token=abc"],
    ["--executable", "slime-nonexistent-command-9284"],
    ["--name", "invalid name", "--log", "app.log"],
])
def test_invalid_setup_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, options: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["agent", *options, "--once"])
    assert result.exit_code == 1
    assert not (tmp_path / ".slime").exists()


def test_managed_setup_preserves_arguments_and_dry_run(tmp_path: Path) -> None:
    config = tmp_path / ".slime/config.yaml"
    settings = prepare_agent(config, "worker", None, [], sys.executable,
                             ["-c", "print('hello world')"], tmp_path)
    process = settings.services[0].managed_process
    assert process and process.args == ["-c", "print('hello world')"]
    assert settings.dry_run
    assert process.cwd == str(tmp_path)


def test_real_agent_cycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["agent", "--log", "future.log", "--once"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".slime/slime.db").is_file()


def test_live_override_is_not_persisted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(cli, "run", lambda **kwargs: calls.append(kwargs))
    result = CliRunner().invoke(cli.app, ["agent", "--log", "app.log", "--no-dry-run"])
    assert result.exit_code == 0, result.output
    assert calls[0]["dry_run"] is False
    assert load_config(tmp_path / ".slime/config.yaml").dry_run
