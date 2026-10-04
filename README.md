# Slime: Local-First DevOps Incident Agent

Slime is an autonomous, local-first incident detection, investigation, and remediation agent for Linux and Windows hosts. It correlates multi-signal telemetry (metrics, logs, health checks, change events), diagnoses root causes via a tiered decision engine, and executes deterministic, policy-guarded repairs with automated verification.

---

## Architecture

```text
[Telemetry Collectors] ──► [Correlation Engine] ──► [Diagnosis Hierarchy (D1–D5)]
(Metrics, Logs, Health,     (Incident Graph,          ├─ D1: BM25 Verified Memory
 Changes, Journald)          Anomaly Scoring)         ├─ D5: Laya Calibrated Classifier
                                                      ├─ D3: Local LLM (Ollama)
                                                      ├─ D4: Cloud LLM (Opt-in)
                                                      └─ D2: Declarative Runbooks
                                                                     │
[Postmortem & Audit] ◄── [Stability Verifier] ◄── [Safety Policy & Executor]
(SQLite, Postmortems,     (Configured Window,      (9 Typed Actions, Approvals,
 Notifications)           Sampled Probes)          Circuit Breakers, Cooldowns)
```

---

## Quickstart

### 1. Installation
Requires Python 3.10+.

```bash
# Clone and create virtual environment
git clone https://github.com/avirooppal/Slime-self-healing-DevOps.git
cd Slime-self-healing-DevOps
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install with development and dashboard extras
pip install -e ".[dev,dashboard]"
```

### 2. Initialize Configuration
```bash
# Generate baseline config.yaml (refuses to overwrite existing configs)
selfheal init

# Check environment capabilities, collectors, and active tiers
selfheal doctor
```

### 3. Run Autonomous Monitoring
```bash
# Run a single evaluation cycle in default dry-run mode
selfheal run --once

# Inspect correlated incidents
selfheal incidents

# Check agent status, kill switch, and circuit breaker
selfheal status
```

### 4. Interactive Localhost Dashboard
```bash
# Start the monitoring and approval web UI (bound strictly to 127.0.0.1)
selfheal dashboard --port 8080
```
Open `http://127.0.0.1:8080` in your browser.

---

## Configuration (`config.yaml`)

```yaml
database: "slime.db"          # SQLite event and outcome repository
dry_run: true                 # Default: true (set to false for live mutation)
poll_seconds: 5.0             # Collector polling interval
correlation_seconds: 300      # Time window for incident correlation
stability_seconds: 120        # Post-remediation verification window
max_auto_targets: 1           # Maximum concurrent auto-remediation targets
ollama_model: "qwen2.5:3b-instruct" # D3 local LLM model

# Service definitions
services:
  - name: "api"
    container_name: "api-service"
    logs: ["logs/api.log"]
    http_url: "http://127.0.0.1:8000/health"
    depends_on: ["database"]
  - name: "database"
    container_name: "db-service"
    logs: ["logs/db.log"]
    process_pid: 1234

# Safety constraints
safety:
  minimum_confidence: 0.90     # Policy threshold for automated repair
  max_hourly_auto_actions: 5   # Hourly rate limit
  action_cooldown_seconds: 300 # Per-action/target cooldown
  consecutive_failure_limit: 3 # Circuit breaker threshold
```

---

## CLI Reference

| Command | Usage | Description |
|---|---|---|
| `init` | `selfheal init` | Detects host capabilities and writes default `config.yaml`. |
| `doctor` | `selfheal doctor` | Diagnostic audit of telemetry sources, Ollama, and tiers. |
| `run` | `selfheal run [--once]` | Executes monitor, correlator, diagnosis, planner, and executor. |
| `status` | `selfheal status` | Displays circuit breaker state, kill switch, and hourly counters. |
| `incidents` | `selfheal incidents` | Lists active, investigating, escalated, and resolved incidents. |
| `approve` | `selfheal approve --action <act> --target <tgt>` | Authorizes an action requiring human approval by digest. |
| `dry-run` | `selfheal dry-run <true\|false>` | Toggles dry-run execution safety mode in configuration. |
| `kill-switch` | `selfheal kill-switch <true\|false>` | Engages or disengages global emergency mutation halt. |
| `reset-circuit` | `selfheal reset-circuit` | Operator reset of a tripped circuit breaker after human inspection. |
| `reconcile` | `selfheal reconcile <action-id>` | Operator resolution of interrupted or pending attempts. |
| `chaos` | `selfheal chaos --scenario <name>` | Runs non-destructive local chaos and adversarial tests. |
| `bench` | `selfheal bench [--tiers T1,T2] [--json]` | Evaluates detection, diagnosis accuracy, and latency across tiers. |
| `dashboard` | `selfheal dashboard [--port 8080]` | Serves the localhost-only FastAPI dashboard UI. |

---

## Remediation Actions & Safety Model

All remediation actions are registered, strictly typed, and validated against host inventory:

| Action | Safety Tier | Target Required | Rollback Support |
|---|---|---|---|
| `restart_container` | **SAFE** | Container alias | None |
| `restart_service` | **APPROVAL** | Systemd unit | None |
| `reload_service` | **APPROVAL** | Systemd unit | None |
| `kill_runaway_process` | **APPROVAL** | Pinned PID | None |
| `quarantine_tmp_files` | **SAFE** | Quiescent private file | Supported (restore from quarantine) |
| `rotate_log_file` | **SAFE** | Quiescent log file | None |
| `revert_config_file` | **APPROVAL** | Versioned config file | Supported (revert to baseline) |
| `rollback_container_image` | **APPROVAL** | Deployment adapter | Refused on generic containers |
| `remove_dangling_images` | **APPROVAL** | Dangling image ID | None |

### Safety Invariants
1. **Zero Shell Execution**: No arbitrary shell commands can be generated or executed by models.
2. **Untrusted Data Boundary**: Logs, alerts, container names, and model text are untrusted data. They cannot alter diagnosis context or grant authorization.
3. **Circuit Breaker**: Trips automatically after 3 consecutive failures. Requires explicit human reset (`selfheal reset-circuit`).
4. **Zero Credentials in Code/DB**: API keys are forbidden in `config.yaml` and SQLite. Cloud keys must reside exclusively in environment variables (`SLIME_CLOUD_API_KEY`).
5. **Localhost-Only Dashboard**: The dashboard server strictly binds to `127.0.0.1`. Non-localhost client connections are blocked with HTTP 403 Forbidden.

---

## Diagnosis Hierarchy (D1–D5)

Slime evaluates candidate causes through a tiered fallback chain:

1. **D1 Memory Shortcut**: Matches verified historical outcomes via context fingerprints and weighted Jaccard similarity ($\ge 85\%$). Bypasses LLM latency on recurring incidents.
2. **D5 Laya Classifier**: Fast closed-set linear/neural classifier with temperature-calibrated probabilities. Gated by latency ($\le 50\text{ ms}$) and confidence ($\ge 80\%$).
3. **D3 Local LLM (Ollama)**: Bounded 6-step hypothesis loop querying read-only diagnostic tools. Validates outputs via strict Pydantic schemas.
4. **D4 Cloud LLM (Opt-in)**: Sends redacted, summary-only context to external providers. Gated by hourly call and spend caps.
5. **D2 Declarative Runbooks**: Deterministic graph and signature matching (e.g. OOM kills, hang conditions, configuration regressions).
6. **Escalation**: Safe abstention requiring human review if no viable automated path meets the confidence threshold.

---

## Testing & Quality Gate

Run the complete 5-part verification gate:

```bash
# 1. Pytest suite (174 passed, 4 expected platform skips)
pytest -q -ra

# 2. Ruff linter
ruff check selfheal tests

# 3. Mypy static type checker
mypy selfheal --ignore-missing-imports

# 4. Pip dependency consistency
pip check

# 5. Runtime doctor
selfheal doctor
```
