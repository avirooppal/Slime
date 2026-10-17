"""Optional read-only Docker container log collector with durable cursor."""

from datetime import datetime, timezone

from selfheal.models import Event, Kind
from selfheal.remediation.docker_adapter import DockerAdapter
from selfheal.security import sanitize
from selfheal.storage.store import Store


class DockerLogs:
    """Collect bounded recent container logs without shell execution."""

    def __init__(
        self,
        container_name: str,
        service: str,
        store: Store,
        adapter: DockerAdapter | None = None,
    ) -> None:
        """Bind to an explicitly configured container name and local store."""
        self.container_name = container_name
        self.service = service
        self.store = store
        self.adapter = adapter or DockerAdapter()
        self.key = f"docker_logs:{service}:{container_name}"

    def collect(self) -> list[Event]:
        """Read at most 100 recent log lines since the last persisted timestamp."""
        try:
            container = self.adapter.container(self.container_name)
            cursor = self.store.checkpoint(self.key)
            kwargs: dict[str, object] = {"timestamps": True, "tail": 100}
            if cursor:
                try:
                    kwargs["since"] = datetime.fromisoformat(cursor)
                except ValueError:
                    pass
            raw = container.logs(**kwargs)
        except (RuntimeError, OSError):
            return []
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        events: list[Event] = []
        latest_ts: str | None = cursor
        for line in text.splitlines()[:100]:
            line = line.strip()
            if not line:
                continue
            ts = datetime.now(timezone.utc)
            msg = line
            parts = line.split(" ", 1)
            if len(parts) == 2:
                try:
                    parsed = datetime.fromisoformat(parts[0].replace("Z", "+00:00"))
                    if parsed.tzinfo is not None:
                        ts = parsed.astimezone(timezone.utc)
                        msg = parts[1]
                except ValueError:
                    pass
            events.append(
                Event(
                    timestamp=ts,
                    kind=Kind.LOG,
                    service=self.service,
                    source=f"docker:{self.container_name}",
                    evidence=sanitize(msg),
                )
            )
            latest_ts = ts.isoformat()
        if latest_ts:
            self.store.checkpoint(self.key, latest_ts)
        return events
