"""Tests for Phase 9: Localhost-Only FastAPI Dashboard and Security Constraints."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from selfheal.config import Config, Service
from selfheal.interface.cli import app as cli_app
from selfheal.interface.dashboard import create_dashboard_app, run_dashboard
from selfheal.models import Incident, State
from selfheal.storage.store import Store


def test_dashboard_endpoints(tmp_path: Path) -> None:
    """Dashboard serves HTML UI and all JSON APIs correctly."""
    db_path = tmp_path / "dash.db"
    store = Store(db_path)
    config = Config(
        database=str(db_path),
        dry_run=True,
        services=[Service(name="worker", container_name="worker-cnt")],
    )

    # Insert test data into store
    inc = Incident(
        id="inc-test-1",
        state=State.OPEN,
        services=["worker"],
        root_candidates=["worker"],
        flap_count=0,
    )
    store.save_incident(inc)
    store.audit("test_subject", "test_rule", "test_detail")

    fastapi_app = create_dashboard_app(config, store)
    client = TestClient(fastapi_app)

    # 1. HTML index
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "Slime DevOps Agent" in res_index.text
    assert "<!DOCTYPE html>" in res_index.text

    # 2. /api/health
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "healthy"
    assert health_data["dry_run"] is True
    assert health_data["breaker_open"] is False

    # 3. /api/incidents
    res_inc = client.get("/api/incidents")
    assert res_inc.status_code == 200
    inc_data = res_inc.json()
    assert len(inc_data["incidents"]) == 1
    assert inc_data["incidents"][0]["id"] == "inc-test-1"

    # 4. /api/tiers
    res_tiers = client.get("/api/tiers")
    assert res_tiers.status_code == 200
    tiers_data = res_tiers.json()
    assert len(tiers_data["tiers"]) == 5
    tier_names = [t["name"] for t in tiers_data["tiers"]]
    assert "D1 Memory" in tier_names
    assert "D2 Runbooks" in tier_names
    assert "D3 Local LLM" in tier_names

    # 5. /api/approvals & POST /api/approve
    res_appr = client.get("/api/approvals")
    assert res_appr.status_code == 200

    res_post_appr = client.post(
        "/api/approve",
        json={"proposal_id": "digest-12345", "actor": "alice"},
    )
    assert res_post_appr.status_code == 200
    assert res_post_appr.json()["status"] == "approved"
    assert res_post_appr.json()["actor"] == "alice"

    # 6. /api/history
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 200

    # 7. /api/audit
    res_audit = client.get("/api/audit")
    assert res_audit.status_code == 200
    audit_data = res_audit.json()
    assert len(audit_data["audit"]) >= 1

    store.close()


def test_dashboard_localhost_security_middleware(tmp_path: Path) -> None:
    """Dashboard forbids external non-localhost client IPs with 403 Forbidden."""
    db_path = tmp_path / "dash_sec.db"
    store = Store(db_path)
    config = Config(database=str(db_path))

    fastapi_app = create_dashboard_app(config, store)
    # Simulate client from an external IP
    client = TestClient(fastapi_app, client=("192.168.1.100", 54321))

    res = client.get("/api/health")
    assert res.status_code == 403
    assert "strictly localhost-only" in res.json()["error"]
    store.close()


def test_run_dashboard_rejects_external_hosts(tmp_path: Path) -> None:
    """run_dashboard raises ValueError if asked to bind to external interface."""
    config = Config(database=str(tmp_path / "db.sqlite"))
    with pytest.raises(ValueError, match="strictly localhost-only"):
        run_dashboard(config, host="0.0.0.0")

    with pytest.raises(ValueError, match="strictly localhost-only"):
        run_dashboard(config, host="192.168.1.1")


def test_cli_dashboard_command_security_check(tmp_path: Path) -> None:
    """CLI dashboard command rejects non-localhost hosts before starting."""
    runner = CliRunner()
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("dry_run: true\n", encoding="utf-8")

    res = runner.invoke(cli_app, ["dashboard", "--config", str(cfg_file), "--host", "0.0.0.0"])
    assert res.exit_code == 1
    assert "Host '0.0.0.0' is forbidden" in res.output
