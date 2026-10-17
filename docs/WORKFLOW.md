# USER WORKFLOW (source of truth)

Install from local source clone (`selfheal` on PyPI is an unrelated third-party package; this distribution is `slime-selfheal`):
  - `pip install -e .` (or `pip install -e ".[dev]"` for test/type-checking tools)

Day 0 (about 5 minutes)
  1. `selfheal init`: scan the machine (log files, systemd units, Docker
     containers, listening ports, nginx upstreams) and write config.yaml (`dry_run: true`,
     `safety.enabled_actions: []`). The user reviews: services to watch, which are
     CRITICAL (never auto-touched), the dependency map (e.g. nginx -> web app -> worker),
     and maintenance windows.
  2. `selfheal doctor`: report which components are active and why (collectors,
     Ollama found or not, optional extras, enabled actions, host OS support), so the user
     knows what mode they are in.
  3. `selfheal run`: starts in DRY-RUN. It detects and diagnoses; it executes nothing.

Days 1-7 (observe)
  - `selfheal status`: system health, open incidents, active components.
  - `selfheal incidents`: each incident with root-cause hypothesis, evidence,
    proposed fix, and a note: "would have auto-executed" or "would have needed
    approval". The agent builds baselines (normal metric ranges, known log
    templates) during this period; early noise is expected and must be handled
    gracefully (learning period flag, lower alerting).

Week 2 (limited auto-healing)
  - By default `safety.enabled_actions` is `[]` (nothing auto-runs). The user enables
    real execution per action via `selfheal enable-action <actions...>` (e.g. only
    `restart_container` and `rotate_logs` — note that in this example `rotate_logs` and
    `clear_tmp_files` require Linux/macOS and do not run on Windows). Everything else
    stays approval-only or suggest-only. All safety limits remain on.
  - Platform note (which Week 2 actions work on which OS):
    - `restart_managed_process` (`SAFE`) and `kill_runaway_process` (`APPROVAL`): work natively on **Windows, Linux, and macOS** (cross-platform `subprocess` + `psutil` PID/create-time verification).
    - `restart_container` (`SAFE`): **untested on real Docker** on this Windows host (requires the `docker` extra and a reachable Docker daemon; validated in CI / `scripts/linux_trial.sh` on Linux with a live Docker daemon).
    - `rotate_logs` (`SAFE`) and `clear_tmp_files` (`SAFE`): require **Linux or macOS** (POSIX `O_NOFOLLOW` / `dir_fd` directory descriptor APIs; unsupported on Windows).
    - `restart_service` (`APPROVAL`) and `reload_nginx` (`APPROVAL`): require **Linux** (`systemd` / `systemctl`; unsupported on Windows and macOS).
    - `rollback_to_previous_image` (`APPROVAL`): **unsupported** in `NativeBackend` across all OSes until a deployment-preserving adapter is supplied.
    - `rerun_healthcheck` is a read-only diagnostic tool (works on **Windows, Linux, and macOS** without consuming cooldown or hourly action budget).

Normal operation (the user mostly does nothing)
  - Resolved incident: fixed, verified healthy for a stability window, postmortem
    written; the user can skim it via log file, desktop notification or dashboard.
  - Approval request: for riskier actions the agent pauses; the user reviews the
    evidence and runs `selfheal approve <id>` (if multiple proposals are staged,
    `approve` refuses and lists their digests so the user runs `selfheal approve <digest>`).
  - Escalation: on low confidence, failed verification, flapping, or an open
    circuit breaker, the agent stops acting and notifies the user. Only the user
    can reset the circuit breaker (`selfheal reset-circuit` / `selfheal reconcile <action_id>`).

Always available
  - `selfheal kill-switch on|off` stops/allows all actions immediately.
  - `selfheal dry-run` returns to observe-only.
  - Maintenance windows suppress actions during planned work.

Optional, later
  - `selfheal bench` (runs the 7-case smoke test and reports detection, root-cause match,
    proposed fix/abstention match, and false-incident rate) and `selfheal eval` (evaluates
    optional held-out Laya routing gates).
  - `selfheal chaos`: run local bounded fault-injection scenarios (or `--docker-demo`
    against the labeled disposable Compose stack).
  - `selfheal dashboard`: launch the optional localhost-only (`127.0.0.1`) FastAPI
    incident and approval dashboard (`pip install -e ".[dashboard]"`).
  - Cloud fallback: API key via environment variable, spend cap, redacted
    summaries only.
  - Approved and rejected actions feed the learning loop.

Out of scope for auto-repair: novel failures, anything FORBIDDEN, database and
network problems. These are diagnosed and reported, not repaired.
