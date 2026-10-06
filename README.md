# Slime developer documentation

Slime is a local-first self-healing DevOps agent for explicitly configured
services. It monitors signals, groups incidents, diagnoses likely causes,
proposes typed repairs, applies a deterministic safety policy, and verifies recovery.

The local core needs **Python 3.10+**. Docker, a model, a GPU and API keys are
optional. **Repairs are dry-run by default.** The verified native recovery path
starts a stopped or crashed process that Slime is configured to own. Slime does
not fix arbitrary application bugs or automatically discover your infrastructure.

## Install from source

```sh
git clone https://github.com/avirooppal/Slime.git
cd Slime
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
source .venv/bin/activate
```

Commands below assume this environment is activated. If activation is unavailable,
use `.venv\Scripts\slime` on Windows or `.venv/bin/slime` on Linux/macOS from
the repository root. `python -m selfheal` is another entry point; the legacy
`selfheal` command remains compatible with `slime`.

The distribution is `slime-selfheal` and is not published to PyPI.
`pip install selfheal` installs an unrelated package. Omit `[dev]` when you do
not need the test and lint tools.

## First run: monitor your application

From your application's directory, name the sources Slime should observe:

```sh
slime agent --health http://localhost:8000/health --log app.log
```

Use a real readiness endpoint for your application. Either `--health` or `--log`
can be used alone; repeat `--log` for additional files. A missing log file may
be created later by the application.

Slime writes `.slime/config.yaml`, stores SQLite state beside it, and starts
polling. Add `.slime/` to your application's `.gitignore`. Subsequent runs reuse
the saved configuration:

```sh
slime agent
```

Press Ctrl+C to stop monitoring. Use `--once` for one cycle. Its exit code reports
command completion, not a CI assertion that all services are healthy.

Existing configuration is never overwritten by new target options. Edit the
saved file or supply a separate `--config PATH` to create another setup. An
endpoint or log file grants observation only; it does not enable process restarts.

## Try a real recovery locally

The included playground is a disposable HTTP service. It begins offline so you
can observe detection, a dry-run proposal, and actual recovery:

```sh
cd examples/playground
python setup.py
slime agent --once
```

Expect `restart_managed_process` and the `dry_run` policy rule. The application
stays offline. Enable execution for a single cycle:

```sh
slime agent --no-dry-run --once
python check.py
```

Expect execution `success`, verification `Stable`, and healthy JSON containing
the app's PID and uptime. `check.py` also prints the browser-accessible health
URL. The example uses a five-second stability window; the normal default is
120 seconds. Optional diagnosis connection attempts may add startup latency.

Inspect the incident, then stop the disposable service:

```sh
slime incidents --config .slime/config.yaml
python check.py stop
```

Omit `--once` to keep monitoring. Ctrl+C stops the agent, **not its managed child**;
stop monitoring before using `check.py stop`. The stop helper checks the child's
recorded PID and birth time. Immediate repeated failures can trigger cooldown or
flapping protection; the example leaves these protections enabled.

The playground uses a dynamically selected loopback port, its own database and
configuration, and preserves existing setup. See [the playground guide](examples/playground/README.md)
for running a fresh experiment.

## Configure managed processes

In a fresh application directory:

```sh
slime agent --name worker --executable python --arg worker.py
```

This resolves the executable and saves a fixed launch specification. Use
`--arg=-m` for arguments beginning with a dash; repeat `--arg` for each argument.
`--cwd` selects the child working directory and base for relative log paths.
Review the generated configuration before enabling execution:

```sh
slime agent --no-dry-run
```

The CLI override applies only to that run. It does not save `dry_run: false`.
Managed children receive a minimal environment (Windows SystemRoot only; empty
on POSIX), so they do not inherit shell secrets or the agent's cloud key.

For an existing configuration, a managed service looks like this:

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

Executable and working-directory paths must be absolute. Slime records PID and
birth time, refuses duplicate startup when an unowned endpoint is already
healthy, and verifies the configured probe after startup. Without HTTP/TCP
probes it verifies process liveness only. It cannot adopt arbitrary PIDs or
restart an already-running unhealthy process.

## Configuration and commands

`slime agent` defaults to `.slime/config.yaml`. Other operator commands default
to `config.yaml`, so pass the agent configuration explicitly:

| Command | Purpose |
| --- | --- |
| `slime doctor --config .slime/config.yaml` | Inspect configured sources, diagnosis tiers and execution mode. |
| `slime status --config .slime/config.yaml` | Inspect kill switch, circuit breaker, rate limits and pending actions. |
| `slime incidents --config .slime/config.yaml` | Read incident history and optional postmortems. |
| `slime run --config .slime/config.yaml --once` | Run an existing configuration for one cycle. |
| `slime preview` | Display the terminal design with labeled sample metrics. |
| `slime approve`, `reconcile` | Approve a staged proposal or reconcile an interrupted action. |
| `slime dry-run`, `kill-switch`, `reset-circuit` | Manage local safety controls. |
| `slime chaos`, `bench`, `eval` | Run fault scenarios and evaluation tools. |

Use `slime COMMAND --help` for arguments. For manual multi-service setup, run
`slime init`, edit the generated `config.yaml`, then run `slime doctor` and
`slime run --once`. The [annotated configuration](config.example.yaml) describes
available settings. Relative paths in manually authored configurations should
be reviewed against the directory from which you run Slime; absolute paths are
recommended for repeatable operation.

## Preview and dashboard

```sh
slime preview
slime preview --output scratch/slime-preview.svg
slime preview --output scratch/slime-preview.html
```

The terminal preview is a static design with **sample data**, not live telemetry.
It shows service health, incidents, verified repairs, recovery time, host
resources, safety controls and recent activity. It does not start services or
read your database.

The optional browser dashboard reads configured local agent state:

```sh
# Install from the repository root.
python -m pip install -e '.[dashboard]'
# Run from the application directory, or use an absolute config path.
slime dashboard --config .slime/config.yaml
```

Open `http://127.0.0.1:8080`. Run the agent separately to collect observations.
The dashboard binds to loopback and uses a fresh approval token. It is separate
from the terminal preview.

## Runtime architecture

One process coordinates the following stages in `selfheal/runtime.py`:

1. Collect configured health, log, host-metric and change signals.
2. Detect anomalies and correlate related events into incidents.
3. Diagnose using local retrieval, runbooks and optional model tiers.
4. Rank typed action proposals and evaluate the deterministic safety policy.
5. Execute permitted actions, verify stability, and record outcomes/postmortems.

| Source directory | Responsibility |
| --- | --- |
| `selfheal/collectors`, `signals` | Read sources, mine log templates and detect anomalies. |
| `selfheal/correlator`, `storage` | Correlate dependencies and persist incidents/audit records in SQLite. |
| `selfheal/diagnosis`, `learning` | BM25 retrieval, runbooks, bounded investigation and verified-outcome learning. |
| `selfheal/planner`, `safety` | Rank proposals; enforce inventory, confidence, approval and execution limits. |
| `selfheal/remediation`, `verifier` | Dispatch registered actions and verify stability. |
| `selfheal/interface` | CLI onboarding, terminal preview and optional browser dashboard. |
| `selfheal/chaos`, `eval` | Isolated scenarios and evaluation tooling. |

D1 local retrieval and D2 runbooks form the baseline. D3 Ollama is optional at
`127.0.0.1:11434`; D4 cloud and D5 Laya require explicit configuration. Laya
also requires a passing held-out evaluation. Optional install extras are
`[docker]`, `[dashboard]`, `[embed]`, `[laya]` and `[cloud]`. Missing optional
components should degrade without disabling the local core.

## Development and validation

From the repository root with `[dev]` installed:

```sh
python -m pytest -q -ra
python -m ruff check selfheal tests
python -m mypy selfheal --ignore-missing-imports
python -m pip check
git diff --check
```

The Windows validation on 2026-10-06 passed **199 tests**, with four platform
skips; lint, type and dependency checks passed. The playground was separately
checked with real HTTP startup, stability verification and identity-bound
cleanup. This is local validation, not a production reliability claim.
GitHub Actions defines Python 3.10/3.12 jobs on Ubuntu and Windows.

When extending Slime, keep collectors read-only and independent. Diagnostic
tools and mutation actions have separate registries. Add repairs as typed
registered actions with inventory validation, policy checks and recovery
verification. Evidence and model output must never grant execution authority.

## Safety boundaries and current limits

Dry-run, minimum confidence, explicit inventory, approvals, cooldown, hourly
budgets, the kill switch and circuit breaker govern execution. Logs, names,
files, probe responses and model output are untrusted evidence. See
[SECURITY.md](SECURITY.md) for the full trust model.

The local managed-process recovery path is tested. Docker/systemd repair and
POSIX file mutations have not been exercised against disposable live targets
on this Windows host. Generic image rollback is unavailable. Cloud redaction
is best-effort, and Laya has not been validated here with a real checkpoint.
Failed startup verification may leave an owned child running and escalate for
operator attention; there is no general rollback for a process launch.

## Further documentation

- [Managed-process validation](docs/managed-process-validation.md)
- [Architecture source](docs/architecture.mmd)
- [Incident lifecycle](docs/incident-states.mmd)
- [Benchmark methodology and limits](docs/public-benchmarks.md)
- [Optional Docker demo](docker-compose.yml)

Historical implementation gates are recorded in `docs/phase*-validation.md`.
