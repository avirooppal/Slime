"""Durable identity tracking for explicitly configured Slime-owned processes."""

import hashlib
import os
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

import psutil

from selfheal.config import ManagedProcessSettings, Service
from selfheal.safety.paths import PathAccess
from selfheal.storage.store import Store

SCHEMA = """
CREATE TABLE IF NOT EXISTS managed_processes (
 service TEXT PRIMARY KEY, spec_hash TEXT NOT NULL, pid INTEGER NOT NULL,
 create_time REAL NOT NULL, started_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class ProcessObservation:
    """An identity-bound read of one configured child process."""

    identity: str
    alive: bool
    specification: str
    executable_stat: tuple[int, int, int, int]
    cwd_stat: tuple[int, int]


class ManagedProcessSupervisor:
    """Start only fixed commands and trust only identities this store launched."""

    def __init__(self, store: Store) -> None:
        self.store = store
        self.store.connection.executescript(SCHEMA)

    @staticmethod
    def _spec(service: Service) -> ManagedProcessSettings:
        """Require an explicit managed-process declaration."""
        if service.managed_process is None:
            raise LookupError("service has no managed process")
        return service.managed_process

    def inspect(self, service: Service) -> ProcessObservation:
        """Read paths, persisted ownership and exact PID birth time."""
        spec = self._spec(service)
        paths = PathAccess([spec.executable, spec.cwd])
        executable = paths.authorize(spec.executable)
        directory = paths.authorize(spec.cwd)
        exe_info, cwd_info = executable.stat(), directory.stat()
        if not stat.S_ISREG(exe_info.st_mode) or not stat.S_ISDIR(cwd_info.st_mode):
            raise ValueError("managed executable or working directory has the wrong type")
        spec_hash = hashlib.sha256(spec.model_dump_json().encode()).hexdigest()
        row = self.store.connection.execute(
            "SELECT spec_hash,pid,create_time FROM managed_processes WHERE service=?",
            (service.name,),
        ).fetchone()
        if row and row[0] != spec_hash:
            raise ValueError("managed process launch specification changed; human review required")
        identity = f"unstarted:{spec_hash}"
        alive = False
        if row:
            identity = f"{row[1]}:{row[2]}"
            try:
                process = psutil.Process(int(row[1]))
                alive = (
                    process.create_time() == float(row[2])
                    and process.is_running()
                    and process.status() != psutil.STATUS_ZOMBIE
                )
            except psutil.Error:
                alive = False
        return ProcessObservation(
            identity, alive, spec_hash,
            (exe_info.st_dev, exe_info.st_ino, exe_info.st_size, exe_info.st_mtime_ns),
            (cwd_info.st_dev, cwd_info.st_ino),
        )

    def start(self, service: Service, expected: ProcessObservation,
              stopped: Callable[[], bool]) -> None:
        """Spawn one owned child after an immediate state recheck, then persist identity."""
        if stopped():
            raise InterruptedError("operator stopped managed process start")
        if self.inspect(service) != expected or expected.alive:
            raise RuntimeError("managed process state changed before start")
        if self.external_probe_healthy(service):
            raise RuntimeError("configured endpoint is already healthy without an owned process")
        spec = self._spec(service)
        if stopped():
            raise InterruptedError("operator stopped managed process start")
        child_env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}
        child = subprocess.Popen(
            [spec.executable, *spec.args], cwd=spec.cwd,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, shell=False, env=child_env,
        )
        try:
            born = psutil.Process(child.pid).create_time()
            with self.store.connection:
                self.store.connection.execute(
                    "INSERT OR REPLACE INTO managed_processes VALUES (?,?,?, ?, datetime('now'))",
                    (service.name, expected.specification, child.pid, born),
                )
                self.store.audit(service.name, "managed_process_started", f"pid={child.pid}")
        except Exception:
            if child.poll() is None:
                child.terminate()
            raise
        if spec.startup_grace_seconds:
            deadline = time.monotonic() + spec.startup_grace_seconds
            while time.monotonic() < deadline:
                if stopped():
                    raise InterruptedError("operator stopped startup readiness check")
                if self.healthy(service) or child.poll() is not None:
                    break
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))

    @staticmethod
    def external_probe_healthy(service: Service) -> bool:
        """Refuse duplicate starts when any configured endpoint is serving traffic."""
        from selfheal.collectors.health_checks import Health

        return any(
            event.attributes.get("healthy") is True
            for event in Health(service).collect()
        )

    def healthy(self, service: Service) -> bool:
        """Require the owned child to remain alive and configured probes to pass."""
        observation = self.inspect(service)
        if not observation.alive:
            return False
        from selfheal.collectors.health_checks import Health

        probes = Health(service).collect()
        return all(event.attributes.get("healthy") is True for event in probes)
