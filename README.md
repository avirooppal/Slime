# Slime

Slime is a local-first, single-process DevOps incident agent. It polls explicitly
configured logs, host metrics, health checks and changes; correlates incidents;
diagnoses with local retrieval and runbooks; proposes typed fixes; and executes
only actions allowed by a deterministic safety policy. It works offline without
Docker, a model, a GPU or an API key. Live mutation is **off by default**.

The verified Docker-free repair path restarts a **Slime-owned** child process from
an operator-specified executable and argument list, then checks health for a
stability window. It does not adopt arbitrary PIDs or restart a running but
unhealthy process. See [current validation](docs/managed-process-validation.md)
and [security boundaries](SECURITY.md) before enabling live repair.

## Set up locally

Python 3.10+ is required. From this repository:

```powershell
py -3 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\selfheal init
.venv\Scripts\selfheal doctor
.venv\Scripts\selfheal run --once
```

On Linux/macOS, use `python3 -m venv .venv`, `.venv/bin/python` and
`.venv/bin/selfheal`. The distribution is named `slime-selfheal`; it is not
published to PyPI. `pip install selfheal` refers to an unrelated package.

`init` writes `config.yaml` without overwriting an existing file. Edit that
file to name only the services, files and endpoints Slime should observe. The
generated config and SQLite database are local operator state and are ignored
by Git. The annotated [example config](config.example.yaml) lists available
settings.

For continuous monitoring, run `selfheal run`. It polls at `poll_seconds` until
Ctrl+C. `--once` runs one cycle. Both commands remain dry-run unless you
explicitly set `dry_run: false` or pass `--no-dry-run`.

## Configure a Docker-free repair

This example is for a service Slime is allowed to start and own. Use absolute
paths and a health endpoint that reflects application readiness:

```yaml
services:
  - name: worker
    managed_process:
      executable: /usr/bin/python3
      args: [-m, my_worker]
      cwd: /opt/my_worker
      startup_grace_seconds: 5
    http_url: http://127.0.0.1:9000/health
```

Run `selfheal doctor`, then `selfheal run --once` to review the proposal. After
reviewing the exact command, paths and health probe, `selfheal run --no-dry-run`
allows policy-approved repair. Slime stores the child PID and birth time, refuses
a duplicate start if the endpoint is already healthy, and requires the probe to
pass throughout the stability window (120 seconds by default). Without an
HTTP/TCP probe, it can verify liveness only. The child receives a minimal
environment; put required non-secret settings in the fixed launch configuration.

## How the code is organized

| Area | Responsibility |
|---|---|
| `selfheal/collectors`, `signals` | Read configured sources; mine log templates and detect anomalies. |
| `selfheal/correlator`, `storage` | Group events by time/dependencies; persist incidents and audit records in SQLite. |
| `selfheal/diagnosis`, `learning` | BM25 memory, runbooks, bounded read-only investigation, verified-outcome learning. |
| `selfheal/planner`, `safety` | Rank typed proposals; apply inventory, confidence, dry-run, cooldown, breaker and approval rules. |
| `selfheal/remediation`, `verifier` | Dispatch registered actions; check stability and escalate failures. |
| `selfheal/interface`, `chaos`, `eval` | CLI/dashboard, isolated fault harness and benchmark/evaluation commands. |

`selfheal/runtime.py` wires one polling and remediation cycle. Keep collectors
read-only and independent. Diagnostic tools live in a separate registry from
mutation actions. Log text, metric labels, container names and file contents are
untrusted data; they never authorize an action. Model output is validated and
still passes the same deterministic policy.

The baseline diagnosis is D1 local retrieval plus D2 runbooks. D3 Ollama at
`127.0.0.1:11434` is optional. D4 cloud and D5 Laya are disabled unless
configured; the latter also needs a passing held-out evaluation. Optional
install extras are `[docker]`, `[dashboard]`, `[embed]`, `[laya]` and `[cloud]`.
Missing extras should degrade without stopping the local core.

## Operator commands

| Command | Purpose |
|---|---|
| `selfheal doctor` | Show configured collectors, optional tiers and execution mode. |
| `selfheal run [--once]` | Monitor, diagnose, plan and apply policy. |
| `selfheal status` / `selfheal incidents` | Inspect safety state and incident history. |
| `selfheal dry-run`, `kill-switch`, `reset-circuit` | Manage trusted local safety controls. |
| `selfheal approve`, `reconcile` | Approve a staged action or resolve an interrupted attempt. |
| `selfheal chaos`, `bench`, `eval` | Run isolated regression scenarios and evaluations. |
| `selfheal dashboard` | Start the optional loopback-only UI with a fresh approval token. |

Use `selfheal <command> --help` for arguments. The dashboard needs
`pip install -e ".[dashboard]"`; Docker demo faults need `[docker]` and the
optional [Compose file](docker-compose.yml). `docs/demo/` is part of that demo.

## Develop and verify

Run the gate after changes (use `.venv/bin/` on Linux/macOS):

```powershell
.venv\Scripts\python -m pytest -q -ra
.venv\Scripts\ruff check selfheal tests
.venv\Scripts\mypy selfheal --ignore-missing-imports
.venv\Scripts\python -m pip check
git diff --check
```

The latest Windows gate passed **187 tests**, with four platform-specific skips;
see the [validation record](docs/managed-process-validation.md) for exact output.
Historical phase gates remain in `docs/phase*-validation.md`. The standalone
[architecture](docs/architecture.mmd), [incident state diagram](docs/incident-states.mmd),
[benchmark notes](docs/public-benchmarks.md) and [security model](SECURITY.md)
provide the details that should not crowd this README.

## Current limits

The real local-process recovery path is tested. Docker/systemd repair and POSIX
file actions have not been exercised against disposable live targets on this
Windows host. The generic image rollback action is intentionally unavailable.
The chaos benchmark is regression data, not a public benchmark score or proof of
production recovery time. Cloud redaction is best-effort, and Laya has not been
validated with a real checkpoint here. Keep live repair confined to services
whose ownership, executable, health probe and failure mode you have reviewed.
