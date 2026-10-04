"""Bounded binary file tailing with durable cursors and rotation handling."""

import json
import os

from selfheal.collectors.common import check_path, pinned_path
from selfheal.models import Event, Kind
from selfheal.security import sanitize
from selfheal.storage.store import Store


class LogTailer:
    """Tail only a configured file, never follow a changed symlink target."""

    def __init__(self, path: str, service: str, store: Store) -> None:
        """Restore offset and file identity without replaying read bytes."""
        self.original, self.path, self.service, self.store = path, pinned_path(path), service, store
        self.key = "tail:" + str(self.path)
        saved = json.loads(store.checkpoint(self.key) or "{}")
        self.cursor = saved.get("offset", 0)
        self.identity = saved.get("identity")
        self.dropping = saved.get("dropping", False)

    def collect(self) -> list[Event]:
        """Read at most 64 KiB per poll; discard oversized line continuations."""
        path = check_path(self.original, self.path)
        events: list[Event] = []
        with path.open("rb") as file:
            stat = os.fstat(file.fileno())
            identity = f"{stat.st_dev}:{stat.st_ino}"
            if self.identity != identity or stat.st_size < self.cursor:
                self.cursor, self.dropping = 0, False
            file.seek(self.cursor)
            budget = 65536
            while budget > 0:
                start = file.tell()
                line = file.readline(min(4097, budget))
                if not line:
                    break
                budget -= len(line)
                if self.dropping:
                    self.dropping = not line.endswith(b"\n")
                    continue
                if not line.endswith(b"\n") and len(line) < 4097:
                    file.seek(start)
                    break
                self.dropping = not line.endswith(b"\n")
                events.append(
                    Event(
                        kind=Kind.LOG,
                        service=self.service,
                        source=str(path),
                        evidence=sanitize(line.decode("utf-8", errors="replace").rstrip("\r\n")),
                    )
                )
            self.cursor, self.identity = file.tell(), identity
        self.store.checkpoint(
            self.key,
            json.dumps(
                {"offset": self.cursor, "identity": self.identity, "dropping": self.dropping}
            ),
        )
        return events
