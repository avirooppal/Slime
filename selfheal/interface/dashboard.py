"""Optional one-page localhost-only FastAPI dashboard for Slime Phase 9."""

from datetime import timedelta
from typing import Any

from pydantic import BaseModel, Field

from selfheal.config import Config
from selfheal.models import State, utcnow
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


class ApprovalRequest(BaseModel):
    """Payload to approve a pending proposal."""

    proposal_id: str = Field(description="Digest/ID of the pending proposal to authorize.")
    actor: str = Field(default="operator", description="Trusted local human operator identifier.")


def create_dashboard_app(config: Config, store: Store | None = None) -> Any:
    """Create and configure the localhost-only FastAPI dashboard."""
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "Dashboard requires 'fastapi' and 'uvicorn'. "
            "Install optional dependencies using: pip install -e '.[dashboard]'"
        )

    db_store = store or Store(config.database)
    safety_state = SafetyState(db_store)

    app = FastAPI(
        title="Slime SelfHeal Dashboard",
        description="Localhost-only monitoring, approvals, tier diagnostics, and outcome history",
        version="0.1.0",
    )

    @app.middleware("http")
    async def localhost_only_middleware(request: Request, call_next: Any) -> Any:
        """Enforce strict localhost-only client access."""
        client_host = request.client.host if request.client else ""
        if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
            return JSONResponse(
                status_code=403,
                content={"error": "Forbidden: Slime dashboard is strictly localhost-only."},
            )
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        """Single-page HTML dashboard with real-time UI components."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Slime DevOps Self-Healing Agent</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --success: #4ade80;
      --warning: #facc15;
      --danger: #f87171;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 24px; line-height: 1.5; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    h1 { font-size: 1.6rem; color: var(--primary); display: flex; align-items: center; gap: 8px; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-info { background: #0369a1; color: #e0f2fe; }
    .badge-success { background: #166534; color: #dcfce7; }
    .badge-warning { background: #854d0e; color: #fef9c3; }
    .badge-danger { background: #991b1b; color: #fee2e2; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 24px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
    .card h2 { font-size: 1.1rem; margin-bottom: 14px; color: var(--text); border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); font-weight: 600; }
    button { background: var(--primary); color: #0f172a; border: none; padding: 6px 14px; border-radius: 4px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
    button:hover { opacity: 0.9; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 6px; }
    .dot-green { background: var(--success); }
    .dot-yellow { background: var(--warning); }
    .dot-red { background: var(--danger); }
    .timestamp { font-size: 0.78rem; color: var(--text-muted); }
    pre { background: #090d16; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; overflow-x: auto; color: #38bdf8; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Slime DevOps Agent</h1>
      <p style="color: var(--text-muted); font-size: 0.9rem;">Local-First, Safety-First Autonomous Self-Healing</p>
    </div>
    <div>
      <span class="badge badge-info" id="mode-badge">Dry-Run</span>
      <span class="badge badge-success" id="breaker-badge">Breaker Closed</span>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h2>System & Tiers</h2>
      <div id="tiers-content">Loading tiers...</div>
    </div>
    <div class="card">
      <h2>Pending Approvals</h2>
      <div id="approvals-content">No approvals pending.</div>
    </div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Active Incidents</h2>
      <div id="incidents-content">Loading incidents...</div>
    </div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Verified Outcomes & Learning History</h2>
      <div id="history-content">Loading outcomes...</div>
    </div>
  </div>

  <div class="grid">
    <div class="card" style="grid-column: 1 / -1;">
      <h2>Recent Audit Log</h2>
      <div id="audit-content">Loading audit log...</div>
    </div>
  </div>

  <script>
    async function loadData() {
      try {
        const [healthRes, tiersRes, incidentsRes, approvalsRes, historyRes, auditRes] = await Promise.all([
          fetch('/api/health').then(r => r.json()),
          fetch('/api/tiers').then(r => r.json()),
          fetch('/api/incidents').then(r => r.json()),
          fetch('/api/approvals').then(r => r.json()),
          fetch('/api/history').then(r => r.json()),
          fetch('/api/audit').then(r => r.json())
        ]);

        // Mode badge
        document.getElementById('mode-badge').textContent = healthRes.dry_run ? 'Dry-Run Mode' : 'Live Mutation Mode';
        document.getElementById('mode-badge').className = healthRes.dry_run ? 'badge badge-info' : 'badge badge-warning';
        document.getElementById('breaker-badge').textContent = healthRes.breaker_open ? 'Breaker Tripped' : 'Breaker Normal';
        document.getElementById('breaker-badge').className = healthRes.breaker_open ? 'badge badge-danger' : 'badge badge-success';

        // Tiers
        let tiersHtml = '<table><tr><th>Tier</th><th>Type</th><th>Status</th></tr>';
        for (const t of tiersRes.tiers) {
          tiersHtml += `<tr><td><strong>${t.name}</strong></td><td>${t.type}</td><td><span class="badge ${t.status === 'active' ? 'badge-success' : 'badge-info'}">${t.status}</span></td></tr>`;
        }
        tiersHtml += '</table>';
        document.getElementById('tiers-content').innerHTML = tiersHtml;

        // Approvals
        if (approvalsRes.approvals.length === 0) {
          document.getElementById('approvals-content').innerHTML = '<p style="color: var(--text-muted); font-size: 0.9rem;">No pending approvals required.</p>';
        } else {
          let appHtml = '<table><tr><th>Proposal ID</th><th>Actor</th><th>Action</th></tr>';
          for (const a of approvalsRes.approvals) {
            appHtml += `<tr><td><code>${a.proposal_id.substring(0, 12)}...</code></td><td>${a.actor}</td><td><button onclick="approve('${a.proposal_id}')">Approve</button></td></tr>`;
          }
          appHtml += '</table>';
          document.getElementById('approvals-content').innerHTML = appHtml;
        }

        // Incidents
        if (incidentsRes.incidents.length === 0) {
          document.getElementById('incidents-content').innerHTML = '<p style="color: var(--text-muted);">No open incidents recorded.</p>';
        } else {
          let incHtml = '<table><tr><th>ID</th><th>State</th><th>Services</th><th>Root Candidates</th><th>Flaps</th></tr>';
          for (const inc of incidentsRes.incidents) {
            incHtml += `<tr><td><code>${inc.id}</code></td><td><span class="badge badge-info">${inc.state}</span></td><td>${inc.services.join(', ')}</td><td>${inc.root_candidates.join(', ')}</td><td>${inc.flap_count}</td></tr>`;
          }
          incHtml += '</table>';
          document.getElementById('incidents-content').innerHTML = incHtml;
        }

        // History
        if (historyRes.outcomes.length === 0) {
          document.getElementById('history-content').innerHTML = '<p style="color: var(--text-muted);">No verified historical outcomes yet.</p>';
        } else {
          let histHtml = '<table><tr><th>Incident</th><th>Action</th><th>Target</th><th>Stable</th><th>Verified At</th></tr>';
          for (const o of historyRes.outcomes) {
            histHtml += `<tr><td><code>${o.incident_id}</code></td><td>${o.action_name}</td><td>${o.target}</td><td><span class="badge ${o.stable ? 'badge-success' : 'badge-danger'}">${o.stable ? 'Yes' : 'No'}</span></td><td class="timestamp">${o.verified_at}</td></tr>`;
          }
          histHtml += '</table>';
          document.getElementById('history-content').innerHTML = histHtml;
        }

        // Audit
        let audHtml = '<table><tr><th>Time</th><th>Subject</th><th>Rule</th><th>Detail</th></tr>';
        for (const row of auditRes.audit) {
          audHtml += `<tr><td class="timestamp">${row.timestamp}</td><td>${row.subject}</td><td><code>${row.rule}</code></td><td>${row.detail}</td></tr>`;
        }
        audHtml += '</table>';
        document.getElementById('audit-content').innerHTML = audHtml;

      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      }
    }

    async function approve(proposalId) {
      if (!confirm('Authorize execution of proposal ' + proposalId + '?')) return;
      try {
        const res = await fetch('/api/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ proposal_id: proposalId, actor: 'dashboard_operator' })
        });
        if (res.ok) {
          alert('Proposal approved successfully.');
          loadData();
        } else {
          const err = await res.json();
          alert('Approval error: ' + (err.detail || err.error));
        }
      } catch (e) {
        alert('Network error approving proposal');
      }
    }

    loadData();
    setInterval(loadData, 5000);
  </script>
</body>
</html>"""

    @app.get("/api/health")
    def get_health() -> dict[str, Any]:
        """System health and safety state overview."""
        is_breaker_open = safety_state.circuit_open()
        failures_row = db_store.connection.execute(
            "SELECT failures FROM safety_control WHERE id=1"
        ).fetchone()
        consecutive_failures = failures_row[0] if failures_row else 0
        return {
            "status": "healthy",
            "dry_run": config.dry_run,
            "breaker_open": is_breaker_open,
            "consecutive_failures": consecutive_failures,
            "active_services": [s.name for s in config.services],
            "timestamp": utcnow().isoformat(),
        }

    @app.get("/api/incidents")
    def get_incidents() -> dict[str, Any]:
        """List persisted incidents across lifecycles."""
        incidents = db_store.incidents()
        return {
            "incidents": [
                {
                    "id": inc.id,
                    "state": inc.state.value if isinstance(inc.state, State) else str(inc.state),
                    "services": inc.services,
                    "root_candidates": inc.root_candidates,
                    "downstream": inc.downstream,
                    "flap_count": inc.flap_count,
                    "opened_at": inc.opened_at.isoformat()
                    if hasattr(inc.opened_at, "isoformat")
                    else str(inc.opened_at),
                }
                for inc in incidents
            ]
        }

    @app.get("/api/approvals")
    def get_approvals() -> dict[str, Any]:
        """List active or pending approvals."""
        rows = db_store.connection.execute(
            "SELECT digest, actor, expires_at FROM approvals WHERE consumed=0 ORDER BY rowid DESC"
        ).fetchall()
        return {
            "approvals": [
                {
                    "proposal_id": r[0],
                    "actor": r[1],
                    "expires_at": r[2],
                }
                for r in rows
            ]
        }

    @app.post("/api/approve")
    def post_approve(req: ApprovalRequest) -> dict[str, Any]:
        """Authorize a pending action proposal with durable audit record."""
        if not req.proposal_id or not req.proposal_id.strip():
            raise HTTPException(status_code=400, detail="Invalid proposal_id")

        actor = req.actor.strip() or "operator"
        expires = (utcnow() + timedelta(seconds=300)).isoformat()
        with db_store.connection:
            db_store.connection.execute(
                "INSERT OR REPLACE INTO approvals VALUES (?, ?, ?, 0)",
                (req.proposal_id.strip(), actor, expires),
            )
            db_store.audit(actor, "dashboard_approval", req.proposal_id.strip())
        return {
            "status": "approved",
            "proposal_id": req.proposal_id,
            "actor": actor,
            "timestamp": utcnow().isoformat(),
        }

    @app.get("/api/history")
    def get_history() -> dict[str, Any]:
        """Retrieve verified historical outcomes."""
        outcomes = db_store.verified_outcomes(only_stable=False)
        return {"outcomes": outcomes}

    @app.get("/api/tiers")
    def get_tiers() -> dict[str, Any]:
        """Return operational status of diagnosis tiers D1-D5."""
        return {
            "tiers": [
                {"name": "D1 Memory", "type": "BM25 Verified Outcomes", "status": "active"},
                {"name": "D2 Runbooks", "type": "Declarative Policy Rules", "status": "active"},
                {
                    "name": "D3 Local LLM",
                    "type": f"Ollama ({config.ollama_model})",
                    "status": "active",
                },
                {
                    "name": "D4 Cloud LLM",
                    "type": "Opt-in Cloud LLM",
                    "status": "active" if config.cloud_enabled else "disabled",
                },
                {
                    "name": "D5 Laya",
                    "type": "Opt-in Neural/Linear Classifier",
                    "status": "active" if config.laya_enabled else "disabled",
                },
            ]
        }

    @app.get("/api/audit")
    def get_audit(limit: int = 50) -> dict[str, Any]:
        """Retrieve recent durable audit entries."""
        rows = db_store.connection.execute(
            "SELECT timestamp, subject, rule, detail FROM audit_log ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return {
            "audit": [
                {
                    "timestamp": r[0],
                    "subject": r[1],
                    "rule": r[2],
                    "detail": r[3],
                }
                for r in rows
            ]
        }

    return app


def run_dashboard(config: Config, host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the localhost-only FastAPI dashboard."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            f"Security violation: Dashboard is strictly localhost-only. Host '{host}' is forbidden."
        )

    app = create_dashboard_app(config)
    uvicorn.run(app, host=host, port=port, log_level="info")
