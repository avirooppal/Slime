# Slime: Local-First DevOps Incident Agent

Slime is a local-first, safety-first autonomous DevOps incident investigation and remediation agent for Python 3.10+.
**All Phases 1–9 are fully implemented, verified, and operational**:
- **Phase 1**: Signal collection (metrics, logs, journald, health checks, change detection), Drain3 log clustering, statistical anomaly alerts, and graph-aware incident correlation.
- **Phase 2**: Nine registered typed actions, deterministic safety policy, durable human approvals, native inventory, and sampled stability verification.
- **Phase 3**: D1 BM25 historical memory retriever, D2 declarative runbooks, pure typed action ranking planner, durable postmortems, and core operational CLI (`run`, `status`, `incidents`, `approve`, `dry-run`, `kill-switch`, `reset-circuit`, `reconcile`).
- **Phase 4**: Non-destructive chaos harness, adversarial injection evaluation, and JSONL ground-truth export.
- **Phase 5**: D3 local LLM (Ollama) hypothesis loop with bounded read-only tool execution and strict fallback.
- **Phase 6**: Learning engine with context fingerprints, multi-attribute Jaccard similarity, and verified outcome shortcut evaluation.
- **Phase 7**: Reproducible incident benchmarking (`selfheal bench`) across public and local dataset adapters with 0.0% unsafe action guarantees.
- **Phase 8**: Optional D4 Cloud LLM (summary-only redaction, env-only API keys, hourly call & spend caps) and optional D5 Laya classifier (calibrated closed-set neural/linear classifier, latency gates, ablation reporting).
- **Phase 9**: Localhost-only FastAPI interactive dashboard (`selfheal dashboard`), multi-channel notifications (desktop toasts, application logging, durable audit trail), and complete security boundaries.

Dry-run mode is enabled by default. No cloud API keys or external telemetry are required for complete operation.

---

## Quickstart

### 1. Environment Setup
```powershell
# Windows PowerShell
python -m venv .venv
.venv/Scripts/python -m pip install --upgrade pip
.venv/Scripts/python -m pip install -e ".[dev,dashboard]"
```
*(On Linux/macOS, use `.venv/bin/` instead of `.venv/Scripts/`)*

### 2. Initialize and Verify Configuration
```powershell
# Create baseline dry-run config.yaml
.venv/Scripts/selfheal init

# Inspect host capabilities and active diagnosis tiers
.venv/Scripts/selfheal doctor

# Run full test suite (174 passed, 4 expected platform skips)
.venv/Scripts/python -m pytest -q -ra
```

### 3. Run Autonomous Monitoring and Self-Healing
```powershell
# Run a single evaluation cycle in default dry-run mode
.venv/Scripts/selfheal run --once

# Inspect open and investigating incidents
.venv/Scripts/selfheal incidents

# Check agent status, circuit breaker, and recent actions
.venv/Scripts/selfheal status
```

### 4. Interactive Localhost Dashboard
```powershell
# Launch the web dashboard on http://127.0.0.1:8080
.venv/Scripts/selfheal dashboard --port 8080
```
The dashboard is strictly localhost-only (`127.0.0.1`) and provides live visibility into:
- System health, dry-run mode, and circuit breaker state
- Active diagnosis tiers (D1–D5)
- Open incidents and root-cause candidate rankings
- Pending human approvals with single-click authorization
- Historical verified outcomes and postmortem reports
- Append-only audit logs

### 5. Reproducible Incident Benchmarking
```powershell
# Benchmark local chaos and adversarial scenarios across tiers
.venv/Scripts/selfheal bench --tiers D2_RUNBOOK,COMBINED

# Export benchmark report as structured JSON
.venv/Scripts/selfheal bench --json --output benchmark_report.json
```

---

## Architectural Overview

### Diagnosis Tier Hierarchy
Slime evaluates candidate root causes and repair actions using a strict fallback hierarchy:
```text
           [Incoming Correlated Incident]
                         │
                         ▼
             [D1 Learning Shortcut]
       (Fingerprint Match >= 85% & Samples >= 2)
              ├── Eligible ──► Fast Verified Repair Proposal
              └── Ineligible / Context Shift
                         │
                         ▼
             [D5 Laya Closed-Set Classifier]
       (Calibrated Confidence >= 80% & Latency <= 50ms)
              ├── Valid ──────► Typed Repair Proposal
              └── Abstain / Disabled / Exceeded Gate
                         │
                         ▼
             [D3 Local LLM (Ollama)]
       (Bounded 6-step hypothesis loop with read-only tools)
              ├── Valid ──────► Typed Repair Proposal
              └── Timeout / Invalid / Unreachable
                         │
                         ▼
             [D4 Opt-In Cloud LLM]
       (Redacted summary-only prompt, spend caps, env-only key)
              ├── Valid ──────► Typed Repair Proposal
              └── Abstain / Disabled / Missing Key / Error
                         │
                         ▼
             [D2 Declarative Runbooks]
       (Deterministic graph & signature matching)
              ├── Valid ──────► Typed Repair Proposal
              └── Abstain
                         │
                         ▼
       [Safe Abstain / Human Review Escalation]
```

### The 9 Typed Remediation Actions
Every remediation action is strictly typed and validated against live host inventory:
| Action | Safety Class | Target Required | Rollback Supported |
|---|---|---|---|
| `restart_container` | SAFE | Exact container alias | No |
| `restart_service` | APPROVAL | Exact systemd unit | No |
| `reload_service` | APPROVAL | Exact systemd unit | No |
| `kill_runaway_process`| APPROVAL | Pinned PID | No |
| `quarantine_tmp_files`| SAFE | Dedicated quiescent tmp file | Yes (restore from quarantine) |
| `rotate_log_file` | SAFE | Dedicated quiescent log file | No |
| `revert_config_file` | APPROVAL | Explicit versioned config file| Yes |
| `rollback_container_image`| APPROVAL | Deployment-specific adapter | Refused on generic containers |
| `remove_dangling_images`| APPROVAL | Exact dangling image ID | No |

---

## Safety Controls & Invariants

1. **Untrusted Data Isolation**: All logs, alerts, container names, model texts, and tool outputs are treated as untrusted data. They can never supply execution permissions or bypass the safety policy.
2. **Deterministic Safety Policy**: Prohibits model-generated shell commands. Remediations must be registered typed actions targeting validated inventory entities.
3. **Dry-Run by Default**: Actions are logged and audited without host mutation unless explicitly overridden by the operator.
4. **Rate Limits & Circuit Breaker**:
   - Maximum 1 target per automated repair cycle.
   - Maximum 5 automated repairs per hour.
   - 300-second per-action/per-target cooldown.
   - Circuit breaker trips after 3 consecutive failures; requires explicit human reset via `.venv/Scripts/selfheal reset-circuit`.
5. **Stability Verification**: Remediations are only marked successful after passing the full stability window (`stability_seconds: 120`). Flapping incidents are immediately escalated.
6. **Zero Secrets in Config or DB**: API keys and credentials are never stored in `config.yaml` or SQLite. Cloud LLM keys are read exclusively from `os.environ`.
7. **Localhost-Only Dashboard**: Binds strictly to `127.0.0.1`. Requests from non-localhost interfaces are rejected with HTTP 403 Forbidden.

---

## CLI Reference

| Command | Description |
|---|---|
| `selfheal init` | Creates baseline dry-run `config.yaml` without overwriting. |
| `selfheal doctor` | Audits collector status, Ollama connectivity, and diagnosis tiers. |
| `selfheal run` | Executes polling, correlation, diagnosis, planning, policy, and repair. |
| `selfheal status` | Displays live agent health, circuit breaker, and recent actions. |
| `selfheal incidents` | Lists active, investigating, escalated, and resolved incidents. |
| `selfheal approve` | Records a single-use human approval for an exact proposal digest. |
| `selfheal dry-run` | Toggles dry-run mode in `config.yaml`. |
| `selfheal kill-switch`| Engages or disengages global emergency stop. |
| `selfheal reset-circuit`| Operator reset of tripped circuit breaker. |
| `selfheal reconcile` | Operator acknowledgement of interrupted or uncertain attempts. |
| `selfheal chaos` | Executes non-destructive synthetic failure and injection scenarios. |
| `selfheal bench` | Runs multi-tier incident benchmarks and reports accuracy and latency. |
| `selfheal dashboard` | Starts the localhost-only FastAPI web monitoring dashboard. |

---

## Validation & Test Suite

The system maintains a 100% passing test baseline across all phases:
```powershell
.venv/Scripts/python -m pytest -q -ra
.venv/Scripts/python -m ruff check selfheal tests
.venv/Scripts/python -m mypy selfheal --ignore-missing-imports
.venv/Scripts/python -m pip check
.venv/Scripts/selfheal doctor
```
See detailed validation reports in `docs/`:
- [Phase 1 Validation](docs/phase1-validation.md)
- [Phase 2 Validation](phase2-validation.md)
- [Phase 3 Validation](docs/phase3-validation.md)
- [Phase 4 Validation](docs/phase4-validation.md)
- [Phase 5 Validation](docs/phase5-validation.md)
- [Phase 6 Validation](docs/phase6-validation.md)
- [Phase 7 Validation](docs/phase7-validation.md)
- [Phase 8 Validation](docs/phase8-validation.md)
- [Phase 9 Validation](docs/phase9-validation.md)
