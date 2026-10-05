"""Opt-in fault injection restricted to Slime's disposable Compose demo."""

from typing import Any

from selfheal.chaos.contracts import FaultType, Scenario
from selfheal.chaos.harness import ChaosHarness
from selfheal.models import Event, Kind, utcnow
from selfheal.remediation.docker_adapter import DockerAdapter

DEMO_PROJECT = "slime-demo"
DEMO_CONTAINERS = {"worker": "slime-demo-worker-1", "web": "slime-demo-web-1"}


def demo_scenarios() -> list[Scenario]:
    """Return only the two disposable Compose faults supported by this adapter."""
    return [
        Scenario(name="demo_worker_stop", fault_type=FaultType.PROCESS_KILL,
                 target_service="worker", expected_root_cause="worker",
                 expected_action="restart_container"),
        Scenario(name="demo_web_outage", fault_type=FaultType.HEALTH_PORT_HANG,
                 target_service="web", expected_root_cause="web",
                 expected_action="restart_container"),
    ]


class DockerDemoHarness(ChaosHarness):
    """Stop and restore only exact, labeled demo containers."""

    def __init__(self, *args: Any, docker: DockerAdapter | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.docker = docker or DockerAdapter()
        self._stopped: list[tuple[Any, str, str]] = []

    @staticmethod
    def _check(container: Any, service: str) -> None:
        """Validate immutable ID and Compose labels before touching a container."""
        labels = container.attrs.get("Config", {}).get("Labels", {})
        if (container.name != DEMO_CONTAINERS[service]
            or labels.get("com.docker.compose.project") != DEMO_PROJECT
            or labels.get("com.docker.compose.service") != service
            or labels.get("org.slime.demo") != "v1"
            or not isinstance(container.id, str) or not container.id):
            raise ValueError("target is not the exact Slime Compose demo container")

    def inject(self, scenario: Scenario) -> Event:
        """Stop one labeled demo container and emit its observed outage."""
        if (scenario.target_service not in DEMO_CONTAINERS
            or (scenario.target_service == "worker" and scenario.fault_type != FaultType.PROCESS_KILL)
            or (scenario.target_service == "web" and scenario.fault_type != FaultType.HEALTH_PORT_HANG)):
            raise ValueError("Docker demo supports only worker stop or web outage")
        container = self.docker.container(DEMO_CONTAINERS[scenario.target_service])
        self._check(container, scenario.target_service)
        if container.status != "running":
            raise ValueError("demo target is not running")
        identity = container.id
        container.kill()
        self._stopped.append((container, scenario.target_service, identity))
        return Event(
            timestamp=utcnow(), service=scenario.target_service,
            kind=Kind.ALERT if scenario.target_service == "worker" else Kind.HEALTH,
            source="docker_demo", severity="error",
            evidence=f"Slime demo {scenario.target_service} container stopped",
            attributes={"reason": "demo container stopped", "healthy": False},
        )

    def cleanup(self) -> None:
        """Restore only the same labeled container that this harness stopped."""
        for container, service, identity in self._stopped:
            container.reload()
            self._check(container, service)
            if container.id != identity:
                raise RuntimeError("demo container identity changed; refusing automatic restore")
            if container.status != "running":
                container.start()
        self._stopped.clear()
        super().cleanup()
