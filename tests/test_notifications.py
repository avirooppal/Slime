"""Tests for Phase 9: Multi-Channel Notifications (Log, Desktop, Audit, and Coordinator Wiring)."""

from pathlib import Path
from unittest.mock import Mock, patch

from selfheal.config import Config, Service
from selfheal.models import Event, Incident, Kind, utcnow
from selfheal.notifications.contracts import NotificationEvent, NotificationLevel
from selfheal.notifications.engine import DesktopNotifier, LogNotifier, NotificationEngine
from selfheal.runtime import Coordinator
from selfheal.storage.store import Store
from tests.safety_fakes import FakeBackend, FakeInventory


def test_log_notifier_records_in_audit_log(tmp_path: Path) -> None:
    """LogNotifier persists notification events to SQLite audit log."""
    db_path = tmp_path / "notify.db"
    store = Store(db_path)
    notifier = LogNotifier(store)

    event = NotificationEvent(
        event_type="incident_detected",
        title="Worker Incident",
        message="Service worker crashed with exit code 137",
        level=NotificationLevel.WARNING,
    )
    success = notifier.send(event)
    assert success is True

    # Check audit log
    rows = store.connection.execute(
        "SELECT subject, rule, detail FROM audit_log WHERE subject='notification'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "notification"
    assert rows[0][1] == "incident_detected"
    assert "Worker Incident" in rows[0][2]
    store.close()


def test_desktop_notifier_graceful_degradation() -> None:
    """DesktopNotifier handles disabled state and OS errors gracefully without throwing."""
    # 1. Disabled
    disabled_notifier = DesktopNotifier(enabled=False)
    event = NotificationEvent(
        event_type="test",
        title="Test",
        message="Test msg",
    )
    assert disabled_notifier.send(event) is False

    # 2. Enabled but subprocess throws
    enabled_notifier = DesktopNotifier(enabled=True)
    with patch("subprocess.run", side_effect=Exception("Display server unavailable")):
        res = enabled_notifier.send(event)
        # Cleanly returns False, never crashes
        assert res is False


def test_notification_engine_dispatching(tmp_path: Path) -> None:
    """NotificationEngine dispatches to all registered channels safely."""
    store = Store(tmp_path / "db.sqlite")
    engine = NotificationEngine(store=store, enable_desktop=False)

    custom_channel = Mock()
    custom_channel.send.return_value = True
    engine.add_notifier(custom_channel)

    evt = engine.notify(
        event_type="repair_executed",
        title="Container Restarted",
        message="worker container was restarted successfully",
        level=NotificationLevel.INFO,
    )

    assert evt.event_type == "repair_executed"
    assert custom_channel.send.called
    store.close()


def test_coordinator_lifecycle_triggers_notifications(tmp_path: Path) -> None:
    """Coordinator dispatches notifications during incident escalation and repair handling."""
    db_path = tmp_path / "slime.db"
    store = Store(db_path)
    inv = FakeInventory()
    backend = FakeBackend()

    config = Config(
        database=str(db_path),
        dry_run=True,
        services=[Service(name="worker", container_name="worker-cnt")],
    )
    coord = Coordinator(
        config=config,
        store=store,
        inventory=inv,
        backend=backend,
    )

    # 1. Incident escalation notification (when no proposals)
    inc_empty = Incident(id="inc-escalate", services=["worker"], root_candidates=["worker"])
    coord.handle_incident(inc_empty)

    rows = store.connection.execute(
        "SELECT rule, detail FROM audit_log WHERE subject='notification' AND rule='incident_escalated'"
    ).fetchall()
    assert len(rows) >= 1
    assert "Incident Escalated: inc-escalate" in rows[0][1]

    # 2. Refused / approval notification when dry-run is on
    ev = Event(
        timestamp=utcnow(),
        service="worker",
        source="log",
        kind=Kind.ALERT,
        evidence="fatal error: container died",
        template_id="oom-1",
    )
    stored_ev = store.event(ev)
    inc_dry = Incident(id="inc-dry", services=["worker"], root_candidates=["worker"], event_ids=[stored_ev.id])
    store.save_incident(inc_dry)

    coord.handle_incident(inc_dry)

    coord.close()
    store.close()
