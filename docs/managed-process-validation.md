# Docker-free self-healing validation — 2026-10-05

The previously verified core passed its gate before this addition. This pass adds
`restart_managed_process` for an explicitly configured Slime-owned child, without
Docker, Ollama, cloud access or an additional core dependency. The existing
deterministic policy still decides whether execution is allowed.

The focused tests launch a real local Python child and a real local HTTP server.
They verify dry-run, HTTP readiness and one-second sampled stability, durable
PID/birth-time ownership, verified outcome and postmortem, refusal after a flap,
secret-environment isolation and refusal to start over an already healthy
unowned endpoint. A CLI test verifies continuous polling and the `--once` exit.
The one-second test window keeps CI fast; the configured
production default is 120 seconds.

Final Windows gate after all changes:

```text
python -m pytest -q -ra
187 passed, 4 skipped, 8 warnings in 30.44s

ruff check selfheal tests
All checks passed!

mypy selfheal --ignore-missing-imports
Success: no issues found in 78 source files

python -m pip check
No broken requirements found.

git diff --check
exit 0 (Git emitted only LF-to-CRLF working-copy notices)

selfheal doctor --config config.example.yaml
Action registry: 10 typed actions; Execution: dry-run (default)
```

The four skips are one symlink privilege case and three POSIX-only native-file
action cases on Windows. The warnings concern optional journald/Laya absence
and an installed FastAPI/Starlette TestClient deprecation. This proves local
process recovery in the test environment; it does not prove production Docker,
systemd, POSIX file actions or a real Laya checkpoint. The process mode does not
adopt external PIDs, recover a running-but-unhealthy child, or atomically pin an
executable against a privileged local file replacement race.
