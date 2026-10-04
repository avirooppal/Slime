"""Transactional local event storage with redaction at the write boundary."""

import json
import sqlite3
from pathlib import Path

from selfheal.models import Event, Incident, utcnow
from selfheal.security import sanitize

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, service TEXT NOT NULL,
 kind TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_service_time ON events(service, timestamp);
CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incident_events (
 incident_id TEXT REFERENCES incidents(id), event_id TEXT REFERENCES events(id),
 PRIMARY KEY(incident_id, event_id));
CREATE TABLE IF NOT EXISTS templates (id TEXT PRIMARY KEY, template TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checkpoints (name TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
 subject TEXT NOT NULL, rule TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
 BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
 BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS hypotheses (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, tier TEXT NOT NULL,
 root_cause TEXT NOT NULL, action_name TEXT, target TEXT,
 params TEXT, confidence REAL NOT NULL, created_at TEXT NOT NULL,
 payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS hypotheses_incident ON hypotheses(incident_id);
CREATE TABLE IF NOT EXISTS verified_outcomes (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, action_name TEXT NOT NULL,
 target TEXT NOT NULL, template_ids TEXT NOT NULL, services TEXT NOT NULL,
 changes TEXT NOT NULL, metrics_pattern TEXT NOT NULL, verified_at TEXT NOT NULL,
 stable INTEGER NOT NULL, payload TEXT NOT NULL, fingerprint TEXT);
CREATE INDEX IF NOT EXISTS verified_outcomes_incident ON verified_outcomes(incident_id);
CREATE TABLE IF NOT EXISTS postmortems (
 incident_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
 markdown TEXT NOT NULL, payload TEXT NOT NULL);
"""


def clean(value: object) -> object:
    """Recursively redact string fields and mapping keys."""
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, dict):
        return {sanitize(str(k)): clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


class Store:
    """Single-process SQLite repository; callers own transaction boundaries."""

    def __init__(self, path: str | Path) -> None:
        """Open a local database and create the Phase 1 schema."""
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.executescript(SCHEMA)
        try:
            self.connection.execute("ALTER TABLE verified_outcomes ADD COLUMN fingerprint TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists

    def close(self) -> None:
        """Close the connection without implicit uncommitted writes."""
        self.connection.close()

    def event(self, event: Event) -> Event:
        """Persist sanitized evidence and return the exact persisted event."""
        safe = Event.model_validate(clean(event.model_dump(mode="json")))
        with self.connection:
            self.connection.execute(
                "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?)",
                (
                    safe.id,
                    safe.timestamp.isoformat(),
                    safe.service,
                    safe.kind.value,
                    safe.model_dump_json(),
                ),
            )
        return safe

    def events(self) -> list[Event]:
        """Read events in deterministic timestamp and insertion order."""
        return [
            Event.model_validate_json(r[0])
            for r in self.connection.execute("SELECT payload FROM events ORDER BY timestamp, rowid")
        ]

    def save_incident(self, incident: Incident) -> None:
        """Upsert incident state and normalized event membership."""
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?, ?)",
                (incident.id, json.dumps(clean(incident.model_dump(mode="json")))),
            )
            for event_id in incident.event_ids:
                self.connection.execute(
                    "INSERT OR IGNORE INTO incident_events VALUES (?, ?)", (incident.id, event_id)
                )

    def incidents(self) -> list[Incident]:
        """Load incidents across restarts."""
        return [
            Incident.model_validate_json(r[0])
            for r in self.connection.execute("SELECT payload FROM incidents ORDER BY rowid")
        ]

    def audit(self, subject: str, rule: str, detail: str) -> None:
        """Append a redacted decision or lifecycle reason."""
        with self.connection:
            self.connection.execute(
                "INSERT INTO audit_log(timestamp,subject,rule,detail) VALUES (?,?,?,?)",
                (utcnow().isoformat(), sanitize(subject), rule, sanitize(detail)),
            )

    def checkpoint(self, name: str, payload: str | None = None) -> str | None:
        """Read or set internal cursor/miner state; never raw log content."""
        if payload is not None:
            with self.connection:
                self.connection.execute(
                    "INSERT OR REPLACE INTO checkpoints VALUES (?,?)", (name, payload)
                )
            return payload
        row = self.connection.execute(
            "SELECT payload FROM checkpoints WHERE name=?", (name,)
        ).fetchone()
        return row[0] if row else None

    def incident_events(self, incident_id: str) -> list[Event]:
        """Read all events associated with a specific incident in timestamp order."""
        rows = self.connection.execute(
            """SELECT e.payload FROM events e
               JOIN incident_events ie ON e.id = ie.event_id
               WHERE ie.incident_id = ?
               ORDER BY e.timestamp, e.rowid""",
            (incident_id,),
        ).fetchall()
        return [Event.model_validate_json(r[0]) for r in rows]

    def save_hypothesis(
        self,
        hypothesis_id: str,
        incident_id: str,
        tier: str,
        root_cause: str,
        action_name: str | None,
        target: str | None,
        params: dict[str, object],
        confidence: float,
        payload: dict[str, object],
    ) -> None:
        """Persist a diagnosis hypothesis for an incident."""
        with self.connection:
            self.connection.execute(
                """INSERT OR REPLACE INTO hypotheses
                   (id, incident_id, tier, root_cause, action_name, target, params, confidence, created_at, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    hypothesis_id,
                    incident_id,
                    tier,
                    sanitize(root_cause, 512),
                    action_name,
                    target,
                    json.dumps(clean(params)),
                    confidence,
                    utcnow().isoformat(),
                    json.dumps(clean(payload)),
                ),
            )

    def hypotheses(self, incident_id: str) -> list[dict[str, object]]:
        """Retrieve stored hypotheses for an incident."""
        rows = self.connection.execute(
            """SELECT id, incident_id, tier, root_cause, action_name, target, params, confidence, created_at, payload
               FROM hypotheses WHERE incident_id = ? ORDER BY rowid""",
            (incident_id,),
        ).fetchall()
        return [
            {
                "id": r[0],
                "incident_id": r[1],
                "tier": r[2],
                "root_cause": r[3],
                "action_name": r[4],
                "target": r[5],
                "params": json.loads(r[6]) if r[6] else {},
                "confidence": r[7],
                "created_at": r[8],
                "payload": json.loads(r[9]) if r[9] else {},
            }
            for r in rows
        ]

    def save_verified_outcome(
        self,
        outcome_id: str,
        incident_id: str,
        action_name: str,
        target: str,
        template_ids: list[str],
        services: list[str],
        changes: list[str],
        metrics_pattern: list[str],
        stable: bool,
        payload: dict[str, object],
        fingerprint: str | None = None,
    ) -> None:
        """Persist a verified repair outcome for BM25 retrieval and learning."""
        with self.connection:
            self.connection.execute(
                """INSERT OR REPLACE INTO verified_outcomes
                   (id, incident_id, action_name, target, template_ids, services, changes, metrics_pattern, verified_at, stable, payload, fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    outcome_id,
                    incident_id,
                    action_name,
                    target,
                    json.dumps(template_ids),
                    json.dumps(services),
                    json.dumps(changes),
                    json.dumps(metrics_pattern),
                    utcnow().isoformat(),
                    1 if stable else 0,
                    json.dumps(clean(payload)),
                    fingerprint,
                ),
            )

    def verified_outcomes(self, only_stable: bool = True) -> list[dict[str, object]]:
        """Retrieve historical verified outcomes for retrieval."""
        query = (
            "SELECT id, incident_id, action_name, target, template_ids, services, changes, metrics_pattern, verified_at, stable, payload, fingerprint "
            "FROM verified_outcomes"
        )
        if only_stable:
            query += " WHERE stable = 1"
        query += " ORDER BY rowid"
        rows = self.connection.execute(query).fetchall()
        return [
            {
                "id": r[0],
                "incident_id": r[1],
                "action_name": r[2],
                "target": r[3],
                "template_ids": json.loads(r[4]),
                "services": json.loads(r[5]),
                "changes": json.loads(r[6]),
                "metrics_pattern": json.loads(r[7]),
                "verified_at": r[8],
                "stable": bool(r[9]),
                "payload": json.loads(r[10]) if r[10] else {},
                "fingerprint": r[11] if len(r) > 11 else None,
            }
            for r in rows
        ]

    def save_postmortem(self, incident_id: str, markdown: str, payload: dict[str, object]) -> None:
        """Persist generated postmortem for an incident."""
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO postmortems (incident_id, created_at, markdown, payload) VALUES (?, ?, ?, ?)",
                (incident_id, utcnow().isoformat(), markdown, json.dumps(clean(payload))),
            )

    def postmortem(self, incident_id: str) -> dict[str, object] | None:
        """Retrieve postmortem for an incident."""
        row = self.connection.execute(
            "SELECT incident_id, created_at, markdown, payload FROM postmortems WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "incident_id": row[0],
            "created_at": row[1],
            "markdown": row[2],
            "payload": json.loads(row[3]) if row[3] else {},
        }

