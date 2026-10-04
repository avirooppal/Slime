"""Metadata/hash changes without persisting config contents or process arguments."""

import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path

import psutil

from selfheal.collectors.common import check_path, command, pinned_path
from selfheal.config import Service
from selfheal.models import Event, Kind
from selfheal.storage.store import Store


class Changes:
    """Track configured files, PID identity, unit state, and kernel version."""

    def __init__(self, service: Service, store: Store) -> None:
        """Pin configured file resolutions before polling."""
        self.service, self.store = service, store
        self.paths = [(p, pinned_path(p)) for p in service.configs]

    def collect(self) -> list[Event]:
        """Emit baselines separately from later observable changes."""
        values: dict[str, str] = {}
        for original, pinned in self.paths:
            path: Path = check_path(original, pinned)
            stat = path.stat()
            if stat.st_size > 4 * 1024 * 1024:
                raise ValueError("config exceeds four MiB hash budget")
            values["file:" + str(path)] = json.dumps(
                {"mtime": stat.st_mtime_ns, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            )
        if self.service.process_pid:
            try:
                p = psutil.Process(self.service.process_pid)
                values["process"] = f"{p.create_time()}:{p.status()}"
            except psutil.Error:
                values["process"] = "absent"
        if self.service.journal_unit and shutil.which("systemctl"):
            try:
                values["unit"] = command(
                    [
                        str(shutil.which("systemctl")),
                        "show",
                        "--property=ActiveState,SubState,ExecMainStartTimestampMonotonic",
                        "--",
                        self.service.journal_unit,
                    ]
                )
            except subprocess.SubprocessError:
                values["unit"] = "unavailable"
        if self.service.name == "host":
            values["kernel"] = platform.release()
        events: list[Event] = []
        for name, value in values.items():
            key = f"change:{self.service.name}:{name}"
            previous = self.store.checkpoint(key)
            if previous != value:
                events.append(
                    Event(
                        kind=Kind.CHANGE,
                        service=self.service.name,
                        source=name,
                        attributes={
                            "baseline": previous is None,
                            "change": name.split(":")[0],
                            "fingerprint": hashlib.sha256(value.encode()).hexdigest(),
                        },
                    )
                )
                self.store.checkpoint(key, value)
        return events
