"""Disposable Docker demo fault-injection boundaries with a fake SDK."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from selfheal.chaos.contracts import FaultType, Scenario
from selfheal.chaos.docker_harness import DockerDemoHarness, demo_scenarios


class DemoContainer:
    """Minimal labeled SDK-shaped container owned by the test."""

    def __init__(self, service: str, project: str = "slime-demo") -> None:
        self.name = f"slime-demo-{service}-1"
        self.id = f"immutable-{service}"
        self.status = "running"
        self.attrs = {"Config": {"Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.service": service,
            "org.slime.demo": "v1",
        }}}
        self.killed = 0
        self.started = 0

    def reload(self) -> None:
        """Refresh fake status without changing identity."""

    def kill(self) -> None:
        """Record one bounded demo fault."""
        self.killed += 1
        self.status = "exited"

    def start(self) -> None:
        """Restore the stopped disposable container."""
        self.started += 1
        self.status = "running"


def test_docker_demo_injects_and_restores_only_labeled_container(tmp_path: Path) -> None:
    """A single opt-in fault is restored after the experiment."""
    worker = DemoContainer("worker")
    adapter = Mock()
    adapter.container.return_value = worker
    harness = DockerDemoHarness(tmp_path, Mock(), docker=adapter)
    event = harness.inject(demo_scenarios()[0])
    assert event.service == "worker"
    assert worker.killed == 1
    adapter.container.assert_called_once_with("slime-demo-worker-1")
    harness.cleanup()
    assert worker.started == 1 and worker.status == "running"


def test_docker_demo_refuses_unlabeled_or_arbitrary_target(tmp_path: Path) -> None:
    """A matching name without project labels cannot be touched."""
    worker = DemoContainer("worker", project="production")
    adapter = Mock()
    adapter.container.return_value = worker
    harness = DockerDemoHarness(tmp_path, Mock(), docker=adapter)
    with pytest.raises(ValueError, match="exact Slime Compose demo"):
        harness.inject(demo_scenarios()[0])
    assert worker.killed == 0
    arbitrary = Scenario(name="other", fault_type=FaultType.PROCESS_KILL,
                         target_service="database", expected_root_cause="database")
    with pytest.raises(ValueError, match="only worker stop or web outage"):
        harness.inject(arbitrary)
    assert adapter.container.call_count == 1


def test_docker_demo_live_daemon_chaos_and_repair(tmp_path: Path) -> None:
    """Exercise DockerDemoHarness and real NativeBackend restart_container when slime-demo stack is running."""
    from selfheal.config import Config, Service
    from selfheal.remediation.docker_adapter import DockerAdapter
    from selfheal.runtime import Coordinator
    from selfheal.safety.contracts import SafetySettings

    adapter = DockerAdapter()
    try:
        worker_cnt = adapter.container("slime-demo-worker-1")
    except Exception:  # noqa: BLE001
        pytest.skip("requires live Docker daemon with running slime-demo stack")

    if worker_cnt.status != "running":
        worker_cnt.start()
        worker_cnt.reload()

    cfg = Config(
        database=str(tmp_path / "live_docker.db"),
        dry_run=False,
        metrics_enabled=False,
        stability_seconds=2,
        safety=SafetySettings(
            enabled_actions=["restart_container"],
            verification_interval_seconds=1,
            verification_timeout_seconds=15,
        ),
        services=[
            Service(
                name="worker",
                container_name="slime-demo-worker-1",
                http_url="http://127.0.0.1:18081/",
            ),
            Service(
                name="web",
                container_name="slime-demo-web-1",
                http_url="http://127.0.0.1:18080/",
            ),
        ],
    )
    coord = Coordinator(cfg)
    try:
        harness = DockerDemoHarness(tmp_path / "chaos_ws", coord, docker=adapter)
        outcome = harness.run_experiment(demo_scenarios()[0])
        assert outcome.detected is True
        assert outcome.diagnosed_root == "worker"
        assert outcome.planned_action == "restart_container"
        assert outcome.policy_allowed is True
        assert outcome.policy_rule == "stability_passed"
        assert outcome.executed is True
        assert outcome.verified_stable is True
        assert outcome.postmortem_generated is True
        repaired = adapter.container("slime-demo-worker-1")
        assert repaired.status == "running"
    finally:
        coord.close()
