"""Durable cooldowns, rate reservations, approvals, circuit breaker and kill switch."""

import hashlib
import json
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from uuid import uuid4

from selfheal.models import utcnow
from selfheal.remediation.contracts import Receipt
from selfheal.safety.contracts import Proposal
from selfheal.security import sanitize
from selfheal.storage.store import Store, clean

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
 id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, name TEXT NOT NULL,
 target TEXT NOT NULL, digest TEXT NOT NULL, started_at TEXT NOT NULL,
 automatic INTEGER NOT NULL, status TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS actions_target_time ON actions(name,target,started_at);
CREATE TABLE IF NOT EXISTS safety_control (
 id INTEGER PRIMARY KEY CHECK(id=1), killed INTEGER NOT NULL DEFAULT 0,
 failures INTEGER NOT NULL DEFAULT 0, circuit_open INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO safety_control(id) VALUES(1);
CREATE TABLE IF NOT EXISTS approvals (
 digest TEXT PRIMARY KEY, actor TEXT NOT NULL, expires_at TEXT NOT NULL,
 consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS action_receipts (
 action_id TEXT PRIMARY KEY REFERENCES actions(id), payload TEXT NOT NULL);
"""


def proposal_digest(proposal: Proposal) -> str:
    """Bind human approval to the exact proposal, parameters and diagnosed revision."""
    return hashlib.sha256(proposal.model_dump_json().encode()).hexdigest()


class SafetyState:
    """Persist controls across agent restarts; fail closed on interrupted attempts."""

    def __init__(self, store: Store, now: Callable[[], datetime] = utcnow) -> None:
        """Initialize state using an injectable aware clock."""
        self.store, self.now = store, now
        self.stop = threading.Event()
        self.store.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Serialize authorization against concurrent SQLite connections."""
        if self.store.connection.in_transaction:
            raise RuntimeError("authorization requires an independent transaction")
        self.store.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.store.connection.commit()
        except BaseException:
            self.store.connection.rollback()
            raise

    def killed(self) -> bool:
        """Read both immediate in-process and persisted global stop controls."""
        return self.stop.is_set() or bool(
            self.store.connection.execute(
                "SELECT killed FROM safety_control WHERE id=1"
            ).fetchone()[0]
        )

    def kill_switch(self, enabled: bool, actor: str) -> None:
        """Operator-only control; stopping first sets the synchronous event."""
        if not actor.strip():
            raise ValueError("operator identity required")
        if enabled:
            self.stop.set()
        with self.transaction():
            self.store.connection.execute(
                "UPDATE safety_control SET killed=? WHERE id=1", (int(enabled),)
            )
            self.store.audit(actor, "kill_switch", str(enabled))
        if not enabled:
            self.stop.clear()

    def circuit_open(self) -> bool:
        """An open circuit or unresolved earlier execution forbids more repairs."""
        opened = self.store.connection.execute(
            "SELECT circuit_open FROM safety_control WHERE id=1"
        ).fetchone()[0]
        pending = self.store.connection.execute(
            "SELECT 1 FROM actions WHERE status IN ('reserved','executing','verifying') LIMIT 1"
        ).fetchone()
        return bool(opened or pending)

    def reset_circuit(self, actor: str) -> None:
        """Require a human API call and refuse reset while an attempt is unresolved."""
        if not actor.strip():
            raise ValueError("operator identity required")
        with self.transaction():
            pending = self.store.connection.execute(
                "SELECT 1 FROM actions WHERE status IN ('reserved','executing','verifying') LIMIT 1"
            ).fetchone()
            if pending:
                raise ValueError("reconcile interrupted attempts before reset")
            self.store.connection.execute(
                "UPDATE safety_control SET failures=0,circuit_open=0 WHERE id=1"
            )
            self.store.audit(actor, "human_circuit_reset", "explicit operator reset")

    def approve(self, proposal: Proposal, actor: str, lifetime_seconds: int = 300) -> None:
        """Record a single-use exact-proposal approval through a trusted human API."""
        if not actor.strip() or not 1 <= lifetime_seconds <= 3600:
            raise ValueError("valid operator and bounded approval lifetime required")
        with self.transaction():
            self.store.connection.execute(
                "INSERT OR REPLACE INTO approvals VALUES(?,?,?,0)",
                (
                    proposal_digest(proposal),
                    sanitize(actor, 128),
                    (self.now() + timedelta(seconds=lifetime_seconds)).isoformat(),
                ),
            )
            self.store.audit(proposal.incident_id, "human_approval", proposal_digest(proposal))

    def approved(self, proposal: Proposal) -> bool:
        """Check exact digest, expiry and consumption without trusting proposal fields."""
        row = self.store.connection.execute(
            "SELECT expires_at,consumed FROM approvals WHERE digest=?", (proposal_digest(proposal),)
        ).fetchone()
        return bool(row and not row[1] and datetime.fromisoformat(row[0]) > self.now())

    def recent_count(self) -> int:
        """Count all auto-authorizations, including failed or aborted reservations."""
        cutoff = (self.now() - timedelta(hours=1)).isoformat()
        return int(
            self.store.connection.execute(
                "SELECT COUNT(*) FROM actions WHERE automatic=1 AND started_at>=?", (cutoff,)
            ).fetchone()[0]
        )

    def cooling_down(self, name: str, target: str, seconds: int) -> bool:
        """Use per-action, per-target attempt times; failed attempts still cool down."""
        cutoff = (self.now() - timedelta(seconds=seconds)).isoformat()
        return (
            self.store.connection.execute(
                "SELECT 1 FROM actions WHERE name=? AND target=? AND started_at>? LIMIT 1",
                (name, target, cutoff),
            ).fetchone()
            is not None
        )

    def reserve(self, proposal: Proposal, target: str, automatic: bool) -> str:
        """Reserve atomically inside the authorization transaction before mutation."""
        action_id = str(uuid4())
        self.store.connection.execute(
            "INSERT INTO actions VALUES(?,?,?,?,?,?,?,?)",
            (
                action_id,
                proposal.incident_id,
                proposal.name,
                target,
                proposal_digest(proposal),
                self.now().isoformat(),
                int(automatic),
                "reserved",
            ),
        )
        self.store.connection.execute(
            "UPDATE approvals SET consumed=1 WHERE digest=?", (proposal_digest(proposal),)
        )
        return action_id

    def status(self, action_id: str, status: str) -> None:
        """Persist one executor milestone independently of collector transactions."""
        with self.transaction():
            previous = {"executing": "reserved", "verifying": "executing"}.get(status)
            if previous is None:
                raise ValueError("illegal action status")
            cursor = self.store.connection.execute(
                "UPDATE actions SET status=? WHERE id=? AND status=?", (status, action_id, previous)
            )
            if cursor.rowcount != 1:
                raise ValueError("unknown action or illegal action transition")
            self.store.audit(action_id, "action_status", status)

    def finish(self, action_id: str, success: bool, failure_limit: int) -> None:
        """Only a verified stable result resets consecutive failure count."""
        with self.transaction():
            allowed = ("verifying",) if success else ("reserved", "executing", "verifying")
            row = self.store.connection.execute(
                "SELECT status FROM actions WHERE id=?", (action_id,)
            ).fetchone()
            if row is None or row[0] not in allowed:
                raise ValueError("only pending attempts can finish; success requires verification")
            self.store.connection.execute(
                "UPDATE actions SET status=? WHERE id=?",
                ("success" if success else "failed", action_id),
            )
            if success:
                self.store.connection.execute("UPDATE safety_control SET failures=0 WHERE id=1")
            else:
                self.store.connection.execute(
                    "UPDATE safety_control SET failures=failures+1 WHERE id=1"
                )
                self.store.connection.execute(
                    "UPDATE safety_control SET circuit_open=1 WHERE id=1 AND failures>=?",
                    (failure_limit,),
                )
            self.store.audit(
                action_id,
                "verified_success" if success else "action_failure",
                "stability passed" if success else "escalation required",
            )

    def save_receipt(self, action_id: str, receipt: Receipt) -> None:
        """Persist redacted recovery metadata, never original file contents."""
        with self.transaction():
            payload = clean(
                {
                    "detail": receipt.detail,
                    "changed": receipt.changed,
                    "rollback_data": receipt.rollback_data,
                }
            )
            self.store.connection.execute(
                "INSERT INTO action_receipts VALUES(?,?)", (action_id, json.dumps(payload))
            )
            self.store.audit(action_id, "execution_receipt", "recovery metadata recorded")

    def reconcile_interrupted(self, action_id: str, actor: str) -> None:
        """Human acknowledges an uncertain attempt; this never retries or assumes success."""
        if not actor.strip():
            raise ValueError("operator identity required")
        with self.transaction():
            cursor = self.store.connection.execute(
                "UPDATE actions SET status='failed' WHERE id=? AND status IN ('reserved','executing','verifying')",
                (action_id,),
            )
            if cursor.rowcount != 1:
                raise ValueError("attempt is not pending")
            self.store.connection.execute(
                "UPDATE safety_control SET circuit_open=1,failures=failures+1 WHERE id=1"
            )
            self.store.audit(
                action_id,
                "human_reconciliation",
                actor + ": uncertain outcome; inspect target manually",
            )
