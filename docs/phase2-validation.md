# Phase 2 validation — 2026-10-04

Phase 1 was reverified before Phase 2 implementation began:

```text
37 passed, 1 skipped in 0.92s
Ruff: All checks passed!
Mypy: no issues in 29 source files
Pip check: No broken requirements found.
Doctor: successful
Live read-only monitoring: 3 observations, 0 incidents
```

Final Phase 2 checks on Windows, Python 3.10.0, project virtual environment:

```text
python -m pytest -q -ra
123 passed, 4 skipped in 2.12s

python -m ruff check selfheal tests
All checks passed!

python -m mypy selfheal --ignore-missing-imports
Success: no issues found in 45 source files

python -m pip check
No broken requirements found.
```

Editable installation succeeded. Both config.example.yaml and the existing
config.yaml validated; both retained dry-run true. Doctor reported the nine typed
actions, active safety API and dry-run execution. A real read-only Monitor.poll()
returned three observations and zero incidents. No monitored host repair ran.
Ollama was reachable but no inference was requested; D3 remains Phase 5.

Tests cover deterministic policy, adversarial inputs, strict schemas, target
identity changes, inventory/precondition/probe timeouts, exact expiring single-use
approvals, critical services, persistent cooldown/budgets/breaker/kill controls,
serialized reservations, interruption reconciliation, rollback refusal and full
incident lifecycle. Virtual time exercises the actual 120-second stability window.
A regression ensures failed resolution reporting never undoes verified recovery.

Docker 7.2.0 was installed only in the project environment to validate the optional
SDK constructor with network and credential access mocked. Mutation adapters use
fake Docker/systemd/process integrations in tests. No real Docker daemon, service
restart, process kill or Docker cleanup result is claimed.

Four skips are explicit: one symlink test requires host privileges; three native
file-mutation cases require POSIX directory-descriptor APIs. Windows path and
opened-handle defenses have deterministic tests. Native file mutation is disabled
on Windows. Linux CI is configured but was not run remotely in this session;
native POSIX mutation remains unverified on this host.

Phase 2 supplies isolated APIs. Runtime diagnosis, planning and repair/approval CLI
wiring are Phase 3. Native image rollback requires a deployment-specific adapter;
the default implementation refuses it. Quarantine preserves bytes and does not
reclaim disk capacity. These limitations are documented rather than simulated as
production capabilities.
