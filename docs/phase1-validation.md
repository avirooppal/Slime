# Phase 1 validation — 2026-10-04

Local environment: Windows, Python 3.10.0, project virtual environment.

```text
python -m pytest -q -ra
37 passed, 1 skipped in 1.26s
SKIPPED: host requires symlink privileges

python -m ruff check selfheal tests
All checks passed!

python -m mypy selfheal --ignore-missing-imports
Success: no issues found in 29 source files

python -m pip check
No broken requirements found.
```

Editable install succeeded. `selfheal init` wrote a default dry-run configuration;
`selfheal doctor` succeeded, reporting aggregate metrics active, journalctl missing
on Windows, optional extras absent, localhost Ollama reachable, and no diagnosis or
execution available in Phase 1. No model was called.
An actual read-only host poll recorded four observations and zero incidents.

Coverage includes strict schemas, inventory validation, redaction, append-only audit,
Drain3 parameter masking and persistence, frequency spikes, statistical anomalies and
change points, graph root candidates, incident merging/lifecycle/maintenance/flap notes,
file partial lines/truncation/oversized lines/restart cursors, mocked journald/systemd/
process/network/metrics, bounded subprocess output and timeout, CLI setup, injection as
data, and a fast file-to-incident integration test with isolated collector failure.

The real symlink test needs host privileges; a separate deterministic path-redirection
test passed. Linux-specific behavior is mocked locally; CI is configured to run on
Linux and Windows but no remote CI result is claimed. Full action-policy adversarial
tests belong to Phase 2, before an executor exists. Phase 2 has not started.
