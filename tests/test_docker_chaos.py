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
