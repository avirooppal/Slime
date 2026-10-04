"""Optional journalctl access for explicitly named systemd units."""

import json
import shutil
from datetime import datetime, timezone

from selfheal.collectors.common import command
from selfheal.models import Event, Kind
from selfheal.security import sanitize
from selfheal.storage.store import Store


class Journal:
    """Read a bounded journal page and persist its opaque cursor."""

    def __init__(self, unit: str, service: str, store: Store) -> None:
        """Require journalctl availability; no shell interpolation."""
        executable = shutil.which("journalctl")
        if not executable:
            raise RuntimeError("journalctl missing")
        self.executable: str = executable
        self.unit, self.service, self.store = unit, service, store

    def collect(self) -> list[Event]:
        """Collect JSON journal entries with a three-second command deadline."""
        args = [self.executable, "--no-pager", "-o", "json", "-n", "100", "--unit", self.unit]
        cursor = self.store.checkpoint("journal:" + self.unit)
        if cursor:
            args += ["--after-cursor", cursor]
        events: list[Event] = []
        for line in command(args).splitlines():
            try:
                entry = json.loads(line)
                timestamp = datetime.fromtimestamp(
                    int(entry["__REALTIME_TIMESTAMP"]) / 1e6, timezone.utc
                )
                events.append(
                    Event(
                        timestamp=timestamp,
                        kind=Kind.LOG,
                        service=self.service,
                        source="journald",
                        evidence=sanitize(str(entry.get("MESSAGE", ""))),
                    )
                )
                self.store.checkpoint("journal:" + self.unit, str(entry["__CURSOR"]))
            except (ValueError, KeyError, TypeError):
                continue
        return events
