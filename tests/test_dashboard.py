"""Tests for Phase 9: Localhost-Only FastAPI Dashboard and Security Constraints."""

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from selfheal.config import Config, Service
from selfheal.interface.cli import app as cli_app
from selfheal.interface.dashboard import create_dashboard_app, run_dashboard
from selfheal.models import Incident, State
from selfheal.safety.contracts import Proposal
from selfheal.safety.state import SafetyState, proposal_digest
from selfheal.storage.store import Store
from tests.safety_fakes import FakeBackend, FakeInventory


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

    # 5. Approval endpoint is disabled unless the server has a session token.
    res_appr = client.get("/api/approvals")
    assert res_appr.status_code == 200

    res_post_appr = client.post(
        "/api/approve",
        json={"proposal_id": "digest-12345"},
    )
    assert res_post_appr.status_code == 403

    # 6. /api/history
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 200

    # 7. /api/audit
    res_audit = client.get("/api/audit")
    assert res_audit.status_code == 200
    audit_data = res_audit.json()
    assert len(audit_data["audit"]) >= 1

    store.close()


def test_dashboard_approval_requires_token_origin_and_live_proposal(tmp_path: Path) -> None:
    """A token cannot authorize an invented digest or a changed inventory revision."""
    db_path = tmp_path / "secure.db"
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=True)
    incident = Incident(id="review-1", state=State.ESCALATED, services=["worker"])
    store.save_incident(incident)
    inventory = FakeInventory()
    backend = FakeBackend()
    proposal = Proposal(
        incident_id=incident.id,
        name="rollback_to_previous_image",
        params={"target": "container.worker", "previous_image": "sha256:" + "a" * 64},
        expected_revision=inventory.live.revision,
        confidence=0.95,
    )
    state = SafetyState(store)
    state.stage_pending(proposal)
    with patch("selfheal.interface.dashboard.NativeInventory", return_value=inventory), patch(
        "selfheal.interface.dashboard.NativeBackend", return_value=backend
    ):
        client = TestClient(create_dashboard_app(config, store, approval_token="a-long-random-token"))
        pending = client.get("/api/approvals").json()["approvals"]
        assert pending[0]["proposal_id"] == proposal_digest(proposal)
        route = "/api/approve"
        payload = {"proposal_id": proposal_digest(proposal)}
        headers = {"origin": "http://testserver", "authorization": "Bearer a-long-random-token"}
        assert client.post(route, json=payload, headers={"origin": "http://testserver"}).status_code == 403
        assert client.post(route, json=payload, headers={"authorization": headers["authorization"]}).status_code == 403
        assert client.post(route, json=payload, headers={**headers, "origin": "http://evil.test"}).status_code == 403
        assert client.post(route, json={"proposal_id": "0" * 64}, headers=headers).status_code == 404
        inventory.live = inventory.live.__class__(
            inventory.live.target, inventory.live.kind, inventory.live.identity,
            "changed-revision", inventory.live.state, inventory.live.healthy,
        )
        assert client.post(route, json=payload, headers=headers).status_code == 409
        inventory.live = inventory.live.__class__(
            inventory.live.target, inventory.live.kind, inventory.live.identity,
            proposal.expected_revision, inventory.live.state, inventory.live.healthy,
        )
        response = client.post(route, json=payload, headers=headers)
        assert response.status_code == 200
        assert state.approved(proposal)
        assert not client.get("/api/approvals").json()["approvals"]
    store.close()


def test_dashboard_localhost_security_middleware(tmp_path: Path) -> None:
    """Dashboard forbids external non-localhost client IPs with 403 Forbidden."""
    db_path = tmp_path / "dash_sec.db"
    store = Store(db_path)
    config = Config(database=str(db_path))

    fastapi_app = create_dashboard_app(config, store)
    # Simulate client from an external IP across Starlette versions
    try:
        client = TestClient(fastapi_app, client=("192.168.1.100", 54321))  # type: ignore[call-arg]
        res = client.get("/api/health")
    except TypeError:
        import asyncio
        import httpx

        async def _req() -> httpx.Response:
            transport = httpx.ASGITransport(app=fastapi_app, client=("192.168.1.100", 54321))
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
                return await ac.get("/api/health")

        res = asyncio.run(_req())

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


def test_session_token_required_on_every_request(tmp_path: Path) -> None:
    """When session_token is configured, every GET and POST request requires the token."""
    db_path = tmp_path / "tok.db"
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=True)
    token = "session-secret-token-999"
    app = create_dashboard_app(config, store, approval_token=token, session_token=token)
    client = TestClient(app)

    # Missing token on GET and POST -> 403
    for path in ("/", "/api/state", "/api/health", "/api/incidents", "/api/approvals"):
        assert client.get(path).status_code == 403
        assert client.get(path, headers={"Authorization": "Bearer wrong-token"}).status_code == 403

    # Valid token via Authorization header -> 200
    auth_headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/", headers=auth_headers).status_code == 200
    assert client.get("/api/state", headers=auth_headers).status_code == 200

    # Valid token via ?token= query sets HttpOnly session cookie for subsequent GETs
    res_cookie = client.get(f"/?token={token}")
    assert res_cookie.status_code == 200
    assert "slime_session" in res_cookie.cookies
    store.close()


def test_dns_rebinding_and_bad_host_rejected(tmp_path: Path) -> None:
    """Reject DNS-rebinding style Host headers on all endpoints."""
    db_path = tmp_path / "host.db"
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=True)
    token = "session-token-host"
    app = create_dashboard_app(config, store, approval_token=token, session_token=token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    for bad_host in (
        "evil.example.com",
        "127.0.0.1.attacker.tld",
        "localhost.rebind.network:8080",
        "192.168.1.50:8080",
        "0.0.0.0:8080",
    ):
        res = client.get("/api/state", headers={**headers, "Host": bad_host})
        assert res.status_code == 403
        assert "Host header" in res.json()["error"]

    for good_host in ("127.0.0.1:8080", "localhost:8080"):
        res_ok = client.get("/api/state", headers={**headers, "Host": good_host})
        assert res_ok.status_code == 200
    store.close()


def test_csrf_and_origin_on_all_state_changing_endpoints(tmp_path: Path) -> None:
    """Approve, reject, kill-switch, and dry-run require valid Origin, CSRF/Bearer header, and record actor 'dashboard'."""
    cfg_path = tmp_path / "config.yaml"
    db_path = tmp_path / "csrf.db"
    cfg_path.write_text(f"database: {db_path.as_posix()}\ndry_run: true\n", encoding="utf-8")
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=True)
    state = SafetyState(store)

    inc = Incident(id="inc-csrf-1", state=State.ESCALATED, services=["worker"])
    store.save_incident(inc)
    inventory = FakeInventory()
    backend = FakeBackend()
    prop1 = Proposal(
        incident_id=inc.id,
        name="rollback_to_previous_image",
        params={"target": "container.worker", "previous_image": "sha256:" + "b" * 64},
        expected_revision=inventory.live.revision,
        confidence=0.95,
    )
    prop2 = Proposal(
        incident_id=inc.id,
        name="restart_service",
        params={"target": "container.worker"},
        expected_revision=inventory.live.revision,
        confidence=0.95,
    )
    state.stage_pending(prop1)
    state.stage_pending(prop2)
    d1 = proposal_digest(prop1)
    d2 = proposal_digest(prop2)

    token = "csrf-secret-token-123"
    with patch("selfheal.interface.dashboard.NativeInventory", return_value=inventory), patch(
        "selfheal.interface.dashboard.NativeBackend", return_value=backend
    ):
        app = create_dashboard_app(
            config, store, approval_token=token, session_token=token, config_path=cfg_path
        )
        client = TestClient(app)

        # Authenticate cookie via GET
        client.get(f"/?token={token}")

        # 1. Cookie-only POST (no Authorization Bearer or X-CSRF-Token header) must fail CSRF check
        for route, body in (
            ("/api/approve", {"proposal_id": d1}),
            ("/api/reject", {"proposal_id": d2}),
            ("/api/kill-switch", {"enabled": True}),
            ("/api/dry-run", {"enabled": False}),
        ):
            res_no_csrf = client.post(route, json=body, headers={"Origin": "http://testserver"})
            assert res_no_csrf.status_code == 403

            # Wrong X-CSRF-Token header must fail even if Authorization Bearer is present
            res_bad_csrf = client.post(
                route,
                json=body,
                headers={
                    "Origin": "http://testserver",
                    "Authorization": f"Bearer {token}",
                    "X-CSRF-Token": "forged-csrf-token",
                },
            )
            assert res_bad_csrf.status_code == 403

            # Bad Origin must fail even with valid CSRF token
            res_bad_origin = client.post(
                route,
                json=body,
                headers={
                    "Origin": "http://attacker.invalid",
                    "X-CSRF-Token": token,
                },
            )
            assert res_bad_origin.status_code == 403

        valid_headers = {
            "Origin": "http://testserver",
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": token,
        }

        # 2. Approve prop1 -> records actor 'dashboard'
        res_app = client.post("/api/approve", json={"proposal_id": d1}, headers=valid_headers)
        assert res_app.status_code == 200
        assert res_app.json()["actor"] == "dashboard"
        assert state.approved(prop1)

        # 3. Reject prop2 -> removes from pending and records actor 'dashboard'
        res_rej = client.post("/api/reject", json={"proposal_id": d2}, headers=valid_headers)
        assert res_rej.status_code == 200
        assert res_rej.json()["actor"] == "dashboard"
        assert state.pending_by_digest(d2) is None

        # 4. Toggle dry-run -> records actor 'dashboard'
        res_dry = client.post("/api/dry-run", json={"enabled": False}, headers=valid_headers)
        assert res_dry.status_code == 200
        assert res_dry.json()["dry_run"] is False
        assert res_dry.json()["actor"] == "dashboard"

        # 5. Engage kill-switch -> records actor 'dashboard'
        res_ks = client.post("/api/kill-switch", json={"enabled": True}, headers=valid_headers)
        assert res_ks.status_code == 200
        assert state.killed() is True
        assert res_ks.json()["actor"] == "dashboard"

        dashboard_audits = store.connection.execute(
            "SELECT rule FROM audit_log WHERE subject='dashboard' ORDER BY id"
        ).fetchall()
        recorded_rules = [r[0] for r in dashboard_audits]
        assert "human_approval" in recorded_rules
        assert "approval_rejected" in recorded_rules
        assert "dry_run_toggle" in recorded_rules
        assert "kill_switch" in recorded_rules
    store.close()


def test_killed_system_cannot_be_reenabled_by_unauthenticated_request(tmp_path: Path) -> None:
    """A killed system cannot be re-enabled without a valid token, Origin, Host, and CSRF header."""
    db_path = tmp_path / "killed.db"
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=False)
    state = SafetyState(store)
    state.kill_switch(True, "sre_operator")
    assert state.killed() is True

    token = "operator-lock-token-777"
    app = create_dashboard_app(config, store, approval_token=token, session_token=token)
    client = TestClient(app)

    # 1. No token, valid Origin
    assert (
        client.post(
            "/api/kill-switch",
            json={"enabled": False},
            headers={"Origin": "http://testserver"},
        ).status_code
        == 403
    )
    assert state.killed() is True

    # 2. Wrong token
    assert (
        client.post(
            "/api/kill-switch",
            json={"enabled": False},
            headers={"Origin": "http://testserver", "Authorization": "Bearer wrong"},
        ).status_code
        == 403
    )
    assert state.killed() is True

    # 3. Missing Origin
    assert (
        client.post(
            "/api/kill-switch",
            json={"enabled": False},
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Token": token},
        ).status_code
        == 403
    )
    assert state.killed() is True

    # 4. Cross-site Origin
    assert (
        client.post(
            "/api/kill-switch",
            json={"enabled": False},
            headers={
                "Origin": "http://evil.example",
                "Authorization": f"Bearer {token}",
                "X-CSRF-Token": token,
            },
        ).status_code
        == 403
    )
    assert state.killed() is True

    # 5. DNS-rebinding Host
    assert (
        client.post(
            "/api/kill-switch",
            json={"enabled": False},
            headers={
                "Host": "rebind.attacker.com",
                "Origin": "http://rebind.attacker.com",
                "Authorization": f"Bearer {token}",
                "X-CSRF-Token": token,
            },
        ).status_code
        == 403
    )
    assert state.killed() is True
    store.close()


def test_xss_payload_in_log_line_never_rendered_as_html(tmp_path: Path) -> None:
    """Evidence with an XSS payload is stored redacted, never injected into HTML, and UI uses zero innerHTML."""
    from selfheal.models import Event, Kind

    db_path = tmp_path / "xss.db"
    store = Store(db_path)
    config = Config(database=str(db_path), dry_run=True)

    xss_payload = "<script>window.__pwned=true</script><img src=x onerror=alert('xss')>"
    ev = store.event(
        Event(
            id="ev-xss-1",
            kind=Kind.LOG,
            service="worker",
            source="/var/log/worker.log",
            evidence=xss_payload,
        )
    )
    inc = Incident(
        id="inc-xss-1",
        state=State.OPEN,
        services=["worker"],
        root_candidates=["worker"],
        event_ids=[ev.id],
    )
    store.save_incident(inc)

    token = "xss-test-token"
    app = create_dashboard_app(config, store, approval_token=token, session_token=token)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {token}"}

    html_doc = client.get("/", headers=headers).text
    # Ensure HTML shell contains no raw untrusted payload and uses zero innerHTML assignments
    assert "<img src=x onerror=alert('xss')>" not in html_doc
    assert ".innerHTML" not in html_doc
    assert "createTextNode" in html_doc

    state_json = client.get("/api/state", headers=headers).json()
    inc_events = state_json["incidents"][0]["events"]
    assert len(inc_events) == 1
    assert inc_events[0]["evidence"] == ev.evidence
    store.close()


def test_demo_database_seeder_and_readonly_enforcement(tmp_path: Path) -> None:
    """Demo database covers all required states and --demo mode refuses mutations."""
    from selfheal.interface.dashboard_demo import seed_demo_database

    token = "demo-token-123"
    cfg, store = seed_demo_database(tmp_path / "demo_ws", preset="default")
    app = create_dashboard_app(
        cfg,
        store=store,
        approval_token=token,
        session_token=token,
        demo_mode=True,
        demo_workspace=tmp_path / "demo_ws",
    )
    client = TestClient(app)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-CSRF-Token": token,
        "Origin": "http://testserver",
    }

    # Default demo state includes healthy service, dry-run incident, pending approval, resolved incident with postmortem, cooldown
    data = client.get("/api/state", headers=headers).json()
    assert data["demo_mode"] is True
    svc_statuses = {s["name"]: s["status"] for s in data["services"]}
    assert "nginx" in svc_statuses
    inc_states = {i["id"]: i["state"] for i in data["incidents"]}
    assert inc_states.get("inc-resolved-01") == "resolved"
    assert inc_states.get("inc-dryrun-02") == "investigating"
    assert inc_states.get("inc-approval-03") == "escalated"
    assert len(data["approvals"]) == 2
    assert len(data["safety"]["cooldowns"]) >= 1

    # Presets cover all_clear, learning, killed, circuit_open, empty
    assert client.get("/api/state?demo_state=all_clear", headers=headers).json()["incidents"][0]["state"] == "resolved"
    learn_data = client.get("/api/state?demo_state=learning", headers=headers).json()
    assert learn_data["mode"]["learning_period"] is True
    killed_data = client.get("/api/state?demo_state=killed", headers=headers).json()
    assert killed_data["safety"]["killed"] is True
    cb_data = client.get("/api/state?demo_state=circuit_open", headers=headers).json()
    assert cb_data["safety"]["circuit_open"] is True
    empty_data = client.get("/api/state?demo_state=empty", headers=headers).json()
    assert len(empty_data["incidents"]) == 0

    # Read-only enforcement on every POST endpoint
    assert client.post("/api/kill-switch", json={"enabled": True}, headers=headers).status_code == 403
    assert client.post("/api/dry-run", json={"enabled": False}, headers=headers).status_code == 403
    assert (
        client.post(
            "/api/approve",
            json={"proposal_id": data["approvals"][0]["proposal_id"]},
            headers=headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/reject",
            json={"proposal_id": data["approvals"][0]["proposal_id"]},
            headers=headers,
        ).status_code
        == 403
    )
    store.close()


def test_terminal_ux_80_col_incidents_detail_status_json_and_doctor(tmp_path: Path) -> None:
    """Verify 80-col incidents list, incidents <id> detail, dry-run vs resolved note, --json, and grouped doctor."""
    import json as json_mod
    import yaml

    from selfheal.interface.dashboard_demo import seed_demo_database

    cfg, store = seed_demo_database(tmp_path / "cli_ux", preset="default")
    store.close()
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False), encoding="utf-8")

    runner = CliRunner()

    # 1. incidents list: every line <= 80 columns, resolved shows actual outcome, dry-run shows would-have note
    res_list = runner.invoke(cli_app, ["incidents", "--config", str(cfg_file)], env={"NO_COLOR": "1"})
    assert res_list.exit_code == 0, res_list.output
    for line in res_list.output.splitlines():
        assert len(line) <= 80, f"Line exceeded 80 cols ({len(line)}): {line}"
    assert "would have auto-executed" in res_list.output
    assert "verified stable" in res_list.output

    # 2. incidents <id> detail view: resolved incident shows actual action & duration, NOT 'would have'
    res_detail = runner.invoke(
        cli_app, ["incidents", "inc-resolved-01", "--config", str(cfg_file)], env={"NO_COLOR": "1"}
    )
    assert res_detail.exit_code == 0
    assert "Incident Detail: inc-resolved-01" in res_detail.output
    assert "restart_container: verified stable (124s)" in res_detail.output
    assert "would have auto-executed" not in res_detail.output

    # 3. incidents --json
    res_inc_json = runner.invoke(cli_app, ["incidents", "--config", str(cfg_file), "--json"])
    assert res_inc_json.exit_code == 0
    parsed_inc = json_mod.loads(res_inc_json.output)
    assert len(parsed_inc["incidents"]) == 3

    # 4. status & status --json match dashboard mode wording
    res_stat = runner.invoke(cli_app, ["status", "--config", str(cfg_file)], env={"NO_COLOR": "1"})
    assert res_stat.exit_code == 0
    assert "DRY-RUN - observe only (no actions execute)" in res_stat.output
    res_stat_json = runner.invoke(cli_app, ["status", "--config", str(cfg_file), "--json"])
    assert res_stat_json.exit_code == 0
    parsed_stat = json_mod.loads(res_stat_json.output)
    assert parsed_stat["mode"] == "DRY-RUN - observe only (no actions execute)"

    # 5. doctor groups (Collectors, Diagnosis, Safety, Platform) and Next step
    res_doc = runner.invoke(cli_app, ["doctor", "--config", str(cfg_file)], env={"NO_COLOR": "1"})
    assert res_doc.exit_code == 0
    for section in ("[Collectors]", "[Diagnosis]", "[Safety]", "[Platform]", "Next step:"):
        assert section in res_doc.output
