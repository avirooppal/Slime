"""Aggregate psutil metrics; no host-wide process command line collection."""

import psutil

from selfheal.models import Event, Kind


class Metrics:
    """Nonblocking CPU/memory sampling and configured disk utilization."""

    def __init__(self, disk_paths: list[str]) -> None:
        """Prime CPU accounting; only configured disks are read."""
        self.disk_paths = disk_paths
        psutil.cpu_percent(interval=None)

    def collect(self) -> list[Event]:
        """Return host aggregate samples without applying alert thresholds."""
        values = [
            ("cpu_percent", psutil.cpu_percent(interval=None)),
            ("memory_percent", psutil.virtual_memory().percent),
        ]
        values += [
            ("disk_percent:" + path, psutil.disk_usage(path).percent) for path in self.disk_paths
        ]
        return [
            Event(
                kind=Kind.METRIC,
                service="host",
                source="psutil",
                attributes={"metric": name, "value": value},
            )
            for name, value in values
        ]
