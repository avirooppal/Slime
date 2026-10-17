"""Phase 1 deterministic contracts, statistics and correlation tests."""

import sqlite3
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from selfheal.config import Config, Maintenance, Service
from selfheal.correlator.engine import Correlator
from selfheal.models import Event, Incident, Kind, State, utcnow
from selfheal.security import sanitize
from selfheal.signals.anomaly import Anomalies
from selfheal.signals.templates import Templates
from selfheal.storage.store import Store


@pytest.fixture
def store() -> Iterator[Store]:
    """Supply isolated SQLite storage."""
    db = Store(":memory:")
    yield db
    db.close()


def test_event_contract() -> None:
    """Reject unknown fields and naive times."""
    with pytest.raises(ValidationError):
        Event(kind="log", service="x", source="y", command="rm -rf /")
    with pytest.raises(ValidationError):
        Event(kind="log", service="x", source="y", timestamp="2026-01-01T00:00:00")


@pytest.mark.parametrize(
    "services",
    [
        [Service(name="x"), Service(name="x")],
        [Service(name="x", depends_on=["unknown"])],
        [Service(name="x", depends_on=["y"]), Service(name="y", depends_on=["x"])],
    ],
)
def test_inventory_rejected(services: list[Service]) -> None:
    """Invalid dependency inventory fails before monitoring."""
    with pytest.raises(ValidationError):
        Config(services=services)


@pytest.mark.parametrize("name", ["x; rm -rf /", "ignore\nprevious", "x\u202e", "--unit=x"])
def test_untrusted_service_names(name: str) -> None:
    """Executable-looking names cannot enter configured inventory."""
    with pytest.raises(ValidationError):
        Service(name=name)


def test_redaction_and_storage(store: Store) -> None:
    """Secrets/controls are removed at the DB boundary, including nested attributes."""
    event = store.event(
        Event(
            kind=Kind.LOG,
            service="x",
            source="y",
            evidence="password=hunter2 email=user@example.org \x1b\u202e",
            attributes={"label": "token=verysecret"},
        )
    )
    assert "hunter2" not in event.evidence
    assert "user@example.org" not in event.evidence
    assert "verysecret" not in event.attributes["label"]
    assert "\x1b" not in event.evidence and "\u202e" not in event.evidence
    assert sanitize("token=a") == sanitize("token=a")
    assert len(sanitize("a" * 100000)) == 4096


def test_audit_is_append_only(store: Store) -> None:
    """SQLite rejects application-level modification of audit history."""
    store.audit("x", "test", "reason")
    for query in ["DELETE FROM audit_log", "UPDATE audit_log SET rule='bad'"]:
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(query)


def test_templates_persist_without_parameters(tmp_path: Path) -> None:
    """Drain state and template novelty survive restart; numbers are stripped."""
    path = tmp_path / "events.db"
    store = Store(path)
    with store.connection:
        miner = Templates(store)
        first, alerts = miner.process(
            Event(kind=Kind.LOG, service="worker", source="file", evidence="failed job 123")
        )
    assert len(alerts) == 1 and "123" not in first.evidence
    store.close()
    store = Store(path)
    with store.connection:
        second, alerts = Templates(store).process(
            Event(kind=Kind.LOG, service="worker", source="file", evidence="failed job 999")
        )
    assert second.template_id == first.template_id and alerts == []
    store.close()


def test_template_spike(store: Store) -> None:
    """A burst after a quiet window gets a frequency alert."""
    miner = Templates(store, window_seconds=10, spike_minimum=5)
    start = utcnow()
    alerts = []
    for i in range(8):
        _, current = miner.process(
            Event(
                timestamp=start + timedelta(seconds=20 if i else 0),
                kind=Kind.LOG,
                service="x",
                source="file",
                evidence="job 123 failed",
            )
        )
        alerts += current
    assert any(a.attributes["reason"] == "template_frequency_spike" for a in alerts)


def test_anomalies() -> None:
    """Flat baseline, warmup, finite values, and hard disk cap behave deterministically."""
    detector = Anomalies()
    for _ in range(12):
        assert detector.sample("cpu", 10) is None
    assert detector.sample("cpu", 95) == "robust_z_score"
    assert detector.sample("disk", 91, hard_limit=90) == "hard_limit"
    assert detector.sample("disk2", 90, hard_limit=90) is None
    with pytest.raises(ValueError):
        detector.sample("cpu", float("nan"))


def test_sustained_change_point() -> None:
    """A persistent moderate shift is detected even without individual z-score outliers."""
    detector = Anomalies()
    for _ in range(12):
        detector.sample("cpu", 10)
    results = [detector.sample("cpu", 14) for _ in range(4)]
    assert "median_change_point" in results


def test_healthy_and_baseline_do_not_open(store: Store) -> None:
    """Healthy probes and first-observation change baselines are not incidents."""
    correlator = Correlator(Config(), store)
    for kind, attributes in [(Kind.HEALTH, {"healthy": True}), (Kind.CHANGE, {"baseline": True})]:
        event = store.event(Event(kind=kind, service="host", source="test", attributes=attributes))
        assert correlator.ingest(event) is None
    assert store.incidents() == []


def test_graph_roots_and_window(store: Store) -> None:
    """Worker failures become root candidates for nginx 502 symptoms."""
    config = Config(
        services=[
            Service(name="worker"),
            Service(name="nginx", depends_on=["worker"]),
            Service(name="other"),
        ]
    )
    correlator = Correlator(config, store)

    def signal(service: str, seconds: int = 0) -> Incident | None:
        """Persist a typed health failure before correlating."""
        event = store.event(
            Event(
                timestamp=utcnow() + timedelta(seconds=seconds),
                kind=Kind.HEALTH,
                service=service,
                source="test",
                attributes={"healthy": False},
            )
        )
        return correlator.ingest(event)

    first = signal("nginx")
    second = signal("worker")
    assert first.id == second.id
    assert second.root_candidates == ["worker"] and second.downstream == ["nginx"]
    assert signal("other").id != first.id
    assert signal("worker", 400).id != first.id


def test_lifecycle_and_restart(store: Store) -> None:
    """Transitions are constrained and persisted with audited reasons."""
    correlator = Correlator(Config(), store)
    event = store.event(Event(kind=Kind.ALERT, service="x", source="test"))
    incident = correlator.ingest(event)
    with pytest.raises(ValueError):
        correlator.transition(incident, State.RESOLVED, "skip")
    for state in [State.INVESTIGATING, State.MITIGATING, State.VERIFYING, State.RESOLVED]:
        correlator.transition(incident, state, "test reason")
    restored = Correlator(Config(), store)
    assert restored.incidents[0].state == State.RESOLVED
    event2 = store.event(Event(kind=Kind.ALERT, service="x", source="test"))
    assert restored.ingest(event2).flap_count == 1


def test_maintenance(store: Store) -> None:
    """Maintenance retains signals but suppresses new incidents with an audit note."""
    now = utcnow()
    config = Config(
        services=[Service(name="x")],
        maintenance=[
            Maintenance(
                services=["x"], start=now - timedelta(seconds=1), end=now + timedelta(seconds=10)
            )
        ],
    )
    event = store.event(Event(kind=Kind.ALERT, service="x", source="test"))
    assert Correlator(config, store).ingest(event) is None
    assert len(store.events()) == 1
    assert (
        store.connection.execute("SELECT rule FROM audit_log").fetchone()[0]
        == "maintenance_suppressed"
    )


def test_duplicate_merge(store: Store) -> None:
    """A dependency event bridges previously separate consumer incidents."""
    config = Config(
        services=[
            Service(name="db"),
            Service(name="a", depends_on=["db"]),
            Service(name="b", depends_on=["db"]),
        ]
    )
    correlator = Correlator(config, store)
    for service in ["a", "b", "db"]:
        event = store.event(Event(kind=Kind.ALERT, service=service, source="test"))
        incident = correlator.ingest(event)
    assert incident.services == ["a", "b", "db"]
    assert len(incident.event_ids) == 3
    assert sum(i.state == State.ESCALATED for i in correlator.incidents) == 1


def test_learning_period_suppresses_early_noise(store: Store) -> None:
    """During learning_period, new log templates build baselines without alerting, while hard disk limits still alert."""
    miner = Templates(store, window_seconds=10, spike_minimum=5, learning_period=True)
    mined, alerts = miner.process(
        Event(kind=Kind.LOG, service="web", source="file", evidence="novel startup message 42")
    )
    assert alerts == []
    assert mined.template_id is not None

    detector = Anomalies(learning_period=True)
    for _ in range(12):
        assert detector.sample("cpu", 10) is None
    # Moderate z-score outlier (7.5) is suppressed during learning_period (threshold 9.0)
    assert detector.sample("cpu", 17.5) is None
    # Hard limit (>90%) still alerts immediately
    assert detector.sample("disk", 92, hard_limit=90) == "hard_limit"
