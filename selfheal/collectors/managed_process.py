"""Read-only liveness events for explicitly managed child processes."""

from selfheal.config import Service
from selfheal.models import Event, Kind
from selfheal.remediation.managed_process import ManagedProcessSupervisor


class ManagedProcessHealth:
    """Report whether Slime's exact recorded child identity remains live."""

    def __init__(self, service: Service, supervisor: ManagedProcessSupervisor) -> None:
        self.service, self.supervisor = service, supervisor

    def collect(self) -> list[Event]:
        """Produce one identity-based health sample without executing anything."""
        observation = self.supervisor.inspect(self.service)
        return [Event(
            kind=Kind.HEALTH, service=self.service.name, source="managed_process",
            severity="info" if observation.alive else "error",
            attributes={"healthy": observation.alive,
                        "reason": "managed process alive" if observation.alive else "managed process exited"},
        )]
