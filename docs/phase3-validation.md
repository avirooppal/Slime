# Phase 3 Validation Record: No-LLM Diagnosis and Remediation Runtime

## Baseline and Environment

- Host: Windows (PowerShell), Python 3.10.0 (`.venv/Scripts/python`)
- Packages: Core dependencies + dev dependencies installed via `pip install -e ".[dev]"`
- Phase gate baseline before Phase 3: 123 passed, 4 skipped in 1.49s (symlink privileges on Windows + 3 POSIX file mutation skips).

---

## What was built in Phase 3

1. **Diagnosis Contracts (`selfheal/diagnosis/contracts.py`)**:
   - `CandidateCause`: hypothesis, root cause service, confidence, evidence event IDs, deciding tier, proposed action, proposed parameters, rationale, and blast radius.
   - `DiagnosisResult`: incident ID, status (`valid`, `abstain`, `invalid`, `timeout`), candidates, notes, and selected property.
   - `DiagnosisContext`: trusted orchestrator status (`valid`/`abstain`), flapping flags, and budget exhaustion, set strictly by the coordinator, never untrusted text.

2. **Additive Storage Migrations (`selfheal/storage/store.py`)**:
   - Created `hypotheses`, `verified_outcomes`, and `postmortems` tables with transaction integrity and indexes.
   - Preserved existing event, incident, and append-only audit trigger schemas.
   - Verified outcome retrieval index covers action names, target identities, template IDs, services, change records, and metric patterns.

3. **D1 Memory: BM25 Historical Retrieval (`selfheal/diagnosis/retrieval.py`)**:
   - Clean cold-start abstention when no verified outcomes exist.
   - BM25Plus retrieval over verified successful outcomes indexing template IDs, service/dependency context, changes, and metric patterns.

4. **D2 Declarative Runbooks (`selfheal/diagnosis/runbooks.py`)**:
   - Deterministic rule engine covering container crashes (OOM/exit code), service health failures, process anomalies, and recent configuration changes.
   - Dependency graph awareness: separates root service failures from downstream 5xx/health symptoms, downgrading downstream-only symptoms so they require human review rather than automatic repair.
   - Disk >90% alerts diagnose pressure but deliberately refuse proposing file quarantine as disk reclamation (per Phase 2 quarantine invariants).

5. **Pure Typed Planner (`selfheal/planner/ranking.py`)**:
   - Pure scoring function: `proven_success_weight * confidence / blast_radius`, with preference for least-invasive actions.
   - Validates candidate actions against `ActionRegistry` and live `Inventory` snapshots; rejects unregistered actions, invalid parameters, or target mismatches.

6. **Postmortem Generator (`selfheal/postmortem/generator.py`)**:
   - Structured markdown report and machine-readable payload containing incident lifecycle status, impacted services, timeline of correlated evidence, root cause hypotheses, remediation outcome, verification details, and operator recommendations.

7. **Runtime Coordinator (`selfheal/runtime.py`)**:
   - Wires single-process polling, correlation, D1/D2 diagnosis, planning, safety authorization, execution via `Executor`, verification across stability window, verified outcome recording upon stability, and postmortem generation.
   - Preserves dry-run default.

8. **Operational CLI Commands (`selfheal/interface/cli.py`)**:
   - `selfheal run`: runs coordinator cycles with `--dry-run` / `--no-dry-run` and `--once` flags.
   - `selfheal status`: reports kill switch status, circuit breaker state, hourly action budget, and pending/interrupted actions.
   - `selfheal incidents`: lists recent incidents with color-coded states and view incident postmortems via `--postmortem <id>`.
   - `selfheal approve`: binds human operator approvals to exact proposal digests and diagnosed revisions.
   - `selfheal dry-run`: configures dry-run default safely in `config.yaml`.
   - `selfheal kill-switch`: engages/disengages global emergency stop.
   - `selfheal reset-circuit`: allows human operator to reset circuit breaker.
   - `selfheal reconcile`: allows human operator to reconcile interrupted/pending actions before circuit reset.

---

## Simulated vs Host Execution

- **Simulated via Injected Test Doubles**:
  - Container crash, process termination, and service restarts in unit and coordinator tests (`tests/safety_fakes.py`: `FakeInventory`, `FakeBackend`, `FakeClock`).
  - Monotonic clock advancement for stability verification without sleeping test threads.
- **Run Directly on Host**:
  - SQLite database persistence, WAL transactions, and append-only audit log triggers.
  - CLI commands (`selfheal doctor`, `selfheal status`, `selfheal incidents`, `selfheal run --once`, `selfheal --help`).
  - Read-only metric collection via `psutil`.
  - BM25 tokenization and ranking via `rank_bm25`.

---

## Phase 3 Gate Verification Output

### Pytest

```text
tests/test_action_lifecycle.py .
tests/test_collectors.py .s................
tests/test_core.py .........................
tests/test_diagnostics.py .................
tests/test_executor.py ............
tests/test_native_actions.py ...........sss.
tests/test_phase3.py ...........
tests/test_safety.py ...................................
=========================== short test summary info ===========================
SKIPPED [1] tests\test_collectors.py:65: host requires symlink privileges
SKIPPED [2] tests\test_native_actions.py:143: native file mutation requires POSIX directory APIs
SKIPPED [1] tests\test_native_actions.py:165: native file mutation requires POSIX directory APIs
134 passed, 4 skipped in 11.80s
```

### Ruff
```text
All checks passed!
```

### Mypy
```text
Success: no issues found in 51 source files
```

### Pip check
```text
No broken requirements found.
```

### Selfheal Doctor
```text
+-----------------------------------------------------------------------------+
| Component       | Status            | Reason                                |
|-----------------+-------------------+---------------------------------------|
| Host metrics    | active            | psutil; aggregate only                |
| docker          | installed         | optional; not activated by the        |
|                 |                   | monitoring CLI                        |
| dashboard       | missing           | optional; not activated by the        |
|                 |                   | monitoring CLI                        |
| embed           | missing           | optional; not activated by the        |
|                 |                   | monitoring CLI                        |
| laya            | missing           | optional; not activated by the        |
|                 |                   | monitoring CLI                        |
| Ollama          | reachable         | qwen2.5:3b-instruct; D3 arrives in    |
|                 |                   | Phase 5                               |
| Diagnosis D1/D2 | active            | D1/D2 active; D3 not implemented      |
| D4/D5           | disabled          | Phase 8; optional cloud/Laya          |
| Safety policy   | active            | deterministic; confidence >= 0.9      |
| Action registry | 9 typed actions   | SAFE/APPROVAL; exact live inventory   |
|                 |                   | required                              |
| Execution       | dry-run (default) | runtime CLI wired in Phase 3          |
+-----------------------------------------------------------------------------+
```

### Selfheal Status
```text
                   Safety Controls & Limits                    
+-------------------------------------------------------------+
| Property          | Value    | Detail                       |
|-------------------+----------+------------------------------|
| Kill switch       | INACTIVE | Global mutation stop         |
| Circuit breaker   | CLOSED   | Requires human reset if open |
| Hourly auto count | 0        | Max: 5                       |
| Dry-run default   | True     | Set in configuration         |
+-------------------------------------------------------------+
```
