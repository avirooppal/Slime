"""Real no-Docker self-healing of one Slime-owned local child process."""

import socket
import sys
import time
from pathlib import Path

import psutil
import pytest

from selfheal.config import Config, ManagedProcessSettings, Service
from selfheal.models import State
from selfheal.remediation.managed_process import ManagedProcessSupervisor
from selfheal.runtime import Coordinator
from selfheal.safety.contracts import SafetySettings
from selfheal.storage.store import Store


def _config(tmp_path: Path, dry_run: bool) -> Config:
    """Create an isolated, fixed command that can only run a sleeping test child."""
    return Config(
        database=str(tmp_path / "slime.db"), dry_run=dry_run,
        metrics_enabled=False, stability_seconds=1,
        safety=SafetySettings(enabled_actions=["restart_managed_process"]),
        services=[Service(
            name="test_worker",
            managed_process=ManagedProcessSettings(
                executable=str(Path(sys.executable).resolve()),
                args=["-c", "import time; time.sleep(30)"], cwd=str(tmp_path.resolve()),
            ),
        )],
    )


def test_managed_process_dry_run_does_not_spawn(tmp_path: Path) -> None:
    """An absent owned process is diagnosed but dry-run leaves the host untouched."""
    coordinator = Coordinator(_config(tmp_path, dry_run=True))
    try:
        results = coordinator.step()
        assert len(results) == 1
        incident, diagnosis, proposals, execution = results[0]
        assert diagnosis.selected and diagnosis.selected.proposed_action == "restart_managed_process"
        assert proposals and proposals[0].proposal.params == {"target": "managed.test_worker"}
        assert execution and execution.rule == "dry_run"
        assert incident.state == State.INVESTIGATING
        assert coordinator.store.connection.execute(
            "SELECT COUNT(*) FROM managed_processes"
        ).fetchone()[0] == 0
    finally:
        coordinator.close()


def test_managed_process_repairs_and_verifies_real_child(tmp_path: Path) -> None:
    """A real owned child is started once and remains live through the stability window."""
    coordinator = Coordinator(_config(tmp_path, dry_run=False))
    owned_pid: int | None = None
    owned_birth: float | None = None
    try:
        results = coordinator.step()
        assert len(results) == 1
        incident, diagnosis, _proposals, execution = results[0]
        assert diagnosis.selected and diagnosis.selected.proposed_action == "restart_managed_process"
        assert execution and execution.status == "success"
        assert execution.verification and execution.verification.stable
        assert execution.verification.elapsed_seconds >= 1
        assert incident.state == State.RESOLVED
        row = coordinator.store.connection.execute(
            "SELECT pid,create_time FROM managed_processes WHERE service='test_worker'"
        ).fetchone()
        assert row is not None
        owned_pid, owned_birth = int(row[0]), float(row[1])
        child = psutil.Process(owned_pid)
        assert child.create_time() == owned_birth and child.is_running()
        assert coordinator.store.verified_outcomes(only_stable=True)
        assert coordinator.store.postmortem(incident.id) is not None
        child.terminate()
        child.wait(timeout=5)
        later = coordinator.step()
        assert len(later) == 1
        flap, _diagnosis, _proposals, refusal = later[0]
        assert flap.flap_count >= 1
        assert refusal and refusal.rule == "flapping_incident"
        assert coordinator.store.connection.execute(
            "SELECT COUNT(*) FROM actions WHERE name='restart_managed_process'"
        ).fetchone()[0] == 1
    finally:
        if owned_pid is not None and owned_birth is not None:
            try:
                child = psutil.Process(owned_pid)
                if child.create_time() == owned_birth:
                    child.terminate()
                    child.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
        coordinator.close()


def test_managed_process_waits_for_http_readiness_and_stability(tmp_path: Path) -> None:
    """Recovery requires a real local HTTP response throughout verification."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    service = Service(
        name="test_http",
        http_url=f"http://127.0.0.1:{port}/",
        managed_process=ManagedProcessSettings(
            executable=str(Path(sys.executable).resolve()),
            args=["-m", "http.server", str(port), "--bind", "127.0.0.1",
                  "--directory", str(tmp_path.resolve())],
            cwd=str(tmp_path.resolve()), startup_grace_seconds=5,
        ),
    )
    config = Config(
        database=str(tmp_path / "http.db"), dry_run=False,
        metrics_enabled=False, stability_seconds=1,
        safety=SafetySettings(enabled_actions=["restart_managed_process"]),
        services=[service],
    )
    coordinator = Coordinator(config)
    owned_pid: int | None = None
    owned_birth: float | None = None
    try:
        results = coordinator.step()
        assert len(results) == 1
        incident, diagnosis, _proposals, execution = results[0]
        assert diagnosis.selected and diagnosis.selected.proposed_action == "restart_managed_process"
        assert execution and execution.status == "success"
        assert execution.verification and execution.verification.stable
        assert incident.state == State.RESOLVED
        assert coordinator.monitor.managed_processes.healthy(service)
        row = coordinator.store.connection.execute(
            "SELECT pid,create_time FROM managed_processes WHERE service='test_http'"
        ).fetchone()
        assert row is not None
        owned_pid, owned_birth = int(row[0]), float(row[1])
    finally:
        if owned_pid is not None and owned_birth is not None:
            try:
                child = psutil.Process(owned_pid)
                if child.create_time() == owned_birth:
                    child.terminate()
                    child.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
        coordinator.close()


def test_unowned_healthy_endpoint_blocks_duplicate_start(tmp_path: Path) -> None:
    """A healthy endpoint with no ownership record must not spawn another copy."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = listener.getsockname()[1]
        config = _config(tmp_path, dry_run=False)
        config.services[0].tcp_host = "127.0.0.1"
        config.services[0].tcp_port = port
        coordinator = Coordinator(config)
        try:
            results = coordinator.step()
            assert len(results) == 1
            _incident, _diagnosis, _proposals, execution = results[0]
            assert execution and execution.status == "refused"
            assert execution.rule == "preconditions_failed"
            assert coordinator.store.connection.execute(
                "SELECT COUNT(*) FROM managed_processes"
            ).fetchone()[0] == 0
        finally:
            coordinator.close()


def test_managed_process_rejects_conflicting_pid_and_secret_args(tmp_path: Path) -> None:
    """Operator input cannot mix static-PID mode or put credentials in arguments."""
    spec = ManagedProcessSettings(executable=str(Path(sys.executable).resolve()),
                                  cwd=str(tmp_path.resolve()))
    with pytest.raises(ValueError, match="either process_pid or managed_process"):
        Service(name="bad", process_pid=123, managed_process=spec)
    with pytest.raises(ValueError, match="credentials are forbidden"):
        ManagedProcessSettings(executable=spec.executable, cwd=spec.cwd,
                               args=["--password=do-not-store"])


def test_managed_child_does_not_inherit_agent_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The managed workload cannot see cloud credentials from Slime's environment."""
    monkeypatch.setenv("SLIME_CLOUD_API_KEY", "test-only-private-value")
    output = tmp_path / "child-env.txt"
    script = (
        "import os,time,pathlib; "
        f"pathlib.Path({str(output)!r}).write_text('|'.join(os.environ)); "
        "time.sleep(10)"
    )
    service = Service(name="env_worker", managed_process=ManagedProcessSettings(
        executable=str(Path(sys.executable).resolve()), args=["-c", script],
        cwd=str(tmp_path.resolve()),
    ))
    store = Store(tmp_path / "env.db")
    supervisor = ManagedProcessSupervisor(store)
    pid: int | None = None
    birth: float | None = None
    try:
        supervisor.start(service, supervisor.inspect(service), lambda: False)
        row = store.connection.execute(
            "SELECT pid,create_time FROM managed_processes WHERE service='env_worker'"
        ).fetchone()
        assert row is not None
        pid, birth = int(row[0]), float(row[1])
        for _ in range(50):
            if output.exists():
                break
            time.sleep(0.02)
        assert output.exists()
        assert "SLIME_CLOUD_API_KEY" not in output.read_text(encoding="utf-8")
    finally:
        if pid is not None and birth is not None:
            try:
                child = psutil.Process(pid)
                if child.create_time() == birth:
                    child.terminate()
                    child.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
        store.close()
