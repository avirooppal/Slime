"""Drain3 templates with persistent miner state and content-derived IDs."""

import base64
import hashlib
from collections import defaultdict, deque
from datetime import datetime

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.persistence_handler import PersistenceHandler
from drain3.template_miner_config import TemplateMinerConfig

from selfheal.models import Event, Kind
from selfheal.security import sanitize
from selfheal.storage.store import Store


class SQLitePersistence(PersistenceHandler):
    """Keep Drain3's trusted internal state in the local database."""

    def __init__(self, store: Store) -> None:
        """Attach to the same transaction as event ingestion."""
        self.store = store

    def save_state(self, state: bytes) -> None:
        """Save serialized sanitized miner state."""
        self.store.checkpoint("drain3", base64.b64encode(state).decode("ascii"))

    def load_state(self) -> bytes | None:
        """Restore the local miner state, if present."""
        state = self.store.checkpoint("drain3")
        return base64.b64decode(state) if state else None


class Templates:
    """Mine logs and detect new templates and bounded frequency spikes."""

    def __init__(
        self,
        store: Store,
        window_seconds: int = 60,
        spike_minimum: int = 20,
        learning_period: bool = False,
    ) -> None:
        """Configure explicit numeric masking and capped Drain3 clusters."""
        config = TemplateMinerConfig()
        config.profiling_enabled = False
        config.drain_max_clusters = 1000
        config.masking_instructions = [MaskingInstruction(r"\b\d+\b", "NUM")]
        self.miner = TemplateMiner(SQLitePersistence(store), config)
        self.store = store
        self.window_seconds = window_seconds
        self.spike_minimum = spike_minimum
        self.learning_period = learning_period
        self.hits: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self.alerted: dict[tuple[str, str], datetime] = {}

    def process(self, event: Event) -> tuple[Event, list[Event]]:
        """Strip variable parameters by storing only sanitized mined templates."""
        result = self.miner.add_log_message(sanitize(event.evidence))
        template = result["template_mined"]
        template_id = hashlib.sha256(template.encode()).hexdigest()[:24]
        exists = self.store.connection.execute(
            "SELECT 1 FROM templates WHERE id=?", (template_id,)
        ).fetchone()
        self.store.connection.execute(
            "INSERT OR IGNORE INTO templates VALUES (?,?)", (template_id, template)
        )
        self.miner.save_state("event checkpoint")
        mined = event.model_copy(update={"evidence": template, "template_id": template_id})
        alerts: list[Event] = []
        key = (event.service, template_id)
        hits = self.hits[key]
        hits.append(event.timestamp)
        while hits and (event.timestamp - hits[0]).total_seconds() > 2 * self.window_seconds:
            hits.popleft()
        recent = sum((event.timestamp - t).total_seconds() <= self.window_seconds for t in hits)
        previous = len(hits) - recent
        cooldown = self.alerted.get(key)
        min_spike = self.spike_minimum * 2 if self.learning_period else self.spike_minimum
        spike = recent >= min_spike and recent > 3 * max(previous, 1)
        is_new_alert = (not exists) and (not self.learning_period)
        if is_new_alert or (
            spike
            and (
                cooldown is None
                or (event.timestamp - cooldown).total_seconds() > self.window_seconds
            )
        ):
            reason = "new_template" if is_new_alert else "template_frequency_spike"
            alerts.append(
                Event(
                    timestamp=event.timestamp,
                    kind=Kind.ALERT,
                    service=event.service,
                    source="templates",
                    evidence=template,
                    severity="warning",
                    template_id=template_id,
                    attributes={"reason": reason, "count": recent},
                )
            )
            self.alerted[key] = event.timestamp
        return mined, alerts
