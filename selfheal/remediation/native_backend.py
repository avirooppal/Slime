"""Bounded concrete platform actions; unsafe deployment reconstruction is refused."""

import shutil
import time
from collections.abc import Callable

import psutil

from selfheal.collectors.common import command
from selfheal.diagnosis.limits import BoundedRead
from selfheal.remediation.contracts import Receipt, TargetParams
from selfheal.safety.contracts import Snapshot
from selfheal.safety.native_inventory import NativeInventory


class NativeBackend:
    """Dispatch a closed set of operations, checking identity again at dispatch."""

    def __init__(self, inventory: NativeInventory) -> None:
        """Share explicit target ownership with read-only inventory."""
        self.inventory = inventory
        self.reader = BoundedRead()

    @staticmethod
    def guard(stopped: Callable[[], bool] | None) -> None:
        """Check the trusted operator stop control immediately before each mutation."""
        if stopped is not None and stopped():
            raise InterruptedError("operator stopped native actions")

    def available(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Refuse unsupported recovery rather than infer credentials or deployment config."""
        if name == "rollback_to_previous_image":
            return False
        if name in {"restart_service", "reload_nginx"}:
            service = self.inventory.services[snapshot.target]
            return bool(
                service.journal_unit
                and shutil.which("systemctl")
                and (name != "reload_nginx" or service.name == "nginx")
            )
        if name in {"clear_tmp_files", "rotate_logs"}:
            return snapshot.state == "quiescent"
        if name == "restart_container":
            service = self.inventory.services[snapshot.target]
            assert service.container_name is not None
            container = self.inventory.docker.container(service.container_name)
            return bool(
                "Health" in container.attrs.get("State", {})
                or service.http_url
                or (service.tcp_host and service.tcp_port)
                or service.journal_unit
                or service.process_pid
            )
        if name == "restart_managed_process":
            return self.inventory.supervisor is not None and snapshot.state == "crashed"
        return name in {
            "restart_container",
            "kill_runaway_process",
        }

    def execute(
        self,
        name: str,
        snapshot: Snapshot,
        params: TargetParams,
        stopped: Callable[[], bool] | None = None,
    ) -> Receipt:
        """No shell interpolation, forced process kill, recursive delete or broad prune."""
        if self.reader.call(lambda: self.inventory.snapshot(params.target), 3, stopped) != snapshot:
            raise RuntimeError("target changed immediately before native dispatch")
        if not self.reader.call(lambda: self.available(name, snapshot, params), 3, stopped):
            raise RuntimeError("native preconditions no longer hold")
        if name == "restart_container" and snapshot.state != "crashed":
            raise RuntimeError("only a crashed container can be restarted automatically")
        if name == "restart_managed_process" and snapshot.state != "crashed":
            raise RuntimeError("only a stopped owned process can be restarted automatically")
        if name in {"clear_tmp_files", "rotate_logs"}:
            return self.inventory.files.execute(name, snapshot, stopped)
        if name == "restart_container":
            service = self.inventory.services[params.target]
            assert service.container_name is not None
            container = self.reader.call(
                lambda: self.inventory.docker.container(str(service.container_name)), 3, stopped
            )
            if container.id != snapshot.identity:
                raise RuntimeError("container identity changed")
            self.guard(stopped)
            container.restart(timeout=2)
            container.reload()
            if container.attrs.get("State", {}).get("Status") == "running":
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    self.guard(stopped)
                    if self.inventory.snapshot(params.target).healthy:
                        break
                    time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        elif name == "restart_managed_process":
            service = self.inventory.services[params.target]
            supervisor = self.inventory.supervisor
            if supervisor is None:
                raise RuntimeError("managed process store unavailable")
            observation = supervisor.inspect(service)
            self.guard(stopped)
            supervisor.start(service, observation, stopped or (lambda: False))
        elif name in {"restart_service", "reload_nginx"}:
            service = self.inventory.services[params.target]
            assert service.journal_unit is not None
            executable = shutil.which("systemctl")
            if not executable:
                raise RuntimeError("systemctl unavailable")
            self.guard(stopped)
            command(
                [
                    executable,
                    "--no-ask-password",
                    "restart" if name == "restart_service" else "reload",
                    "--",
                    service.journal_unit,
                ],
                timeout=10,
            )
        elif name == "kill_runaway_process":
            service = self.inventory.services[params.target]
            assert service.process_pid is not None
            process = psutil.Process(service.process_pid)
            if f"{process.pid}:{process.create_time()}" != snapshot.identity:
                raise RuntimeError("PID was reused")
            self.guard(stopped)
            process.terminate()
        else:
            raise RuntimeError("native action unavailable; use a deployment-specific typed adapter")
        return Receipt("typed native action dispatched; stability verification still required")

    def verify(self, name: str, snapshot: Snapshot, params: TargetParams) -> bool:
        """Require application health for restarts, not merely running state."""
        if name in {"clear_tmp_files", "rotate_logs"}:
            return self.inventory.files.verify(params.target)
        if name == "kill_runaway_process":
            service = self.inventory.services[params.target]
            assert service.process_pid is not None
            try:
                process = psutil.Process(service.process_pid)
                return f"{process.pid}:{process.create_time()}" != snapshot.identity
            except psutil.NoSuchProcess:
                return True
        if name == "restart_managed_process":
            supervisor = self.inventory.supervisor
            if supervisor is None:
                return False
            service = self.inventory.services[params.target]
            observation = supervisor.inspect(service)
            return observation.identity != snapshot.identity and supervisor.healthy(service)
        live = self.inventory.snapshot(params.target)
        return live.identity == snapshot.identity and live.healthy

    def rollback(
        self,
        name: str,
        snapshot: Snapshot,
        receipt: Receipt,
        stopped: Callable[[], bool] | None = None,
    ) -> bool:
        """Only private file quarantine/rotation is safely reversible generically."""
        if name in {"clear_tmp_files", "rotate_logs"}:
            self.guard(stopped)
            return self.inventory.files.rollback(snapshot, receipt, stopped)
        return False
