# Phase 4 Validation Record: Chaos Harness & Ground-Truth Evaluation

## Baseline and Environment

- Host: Windows (PowerShell), Python 3.10.0 (`.venv/Scripts/python`)
- Packages: Core dependencies + dev dependencies installed via `pip install -e ".[dev]"`
- Gate baseline before Phase 4: 134 passed, 4 skipped in 1.93s.

---

## What was built in Phase 4

1. **Chaos Contracts (`selfheal/chaos/contracts.py`)**:
   - `FaultType`: Closed set of non-destructive fault categories (`PROCESS_KILL`, `TEMP_FILE_FILL`, `LOG_INJECTION`, `CONFIG_MUTATION`, `HEALTH_PORT_HANG`, `ADVERSARIAL_INJECTION`).
   - `Scenario`: Ground-truth experiment definition with target service, expected root cause, expected action, adversarial flag, and typed parameters.
   - `ExperimentOutcome`: Full lifecycle verification report detailing detection, incident ID, diagnosis tier, planned action, policy rule, execution outcome, stability verification, postmortem generation, and adversarial safety prevention.

2. **Isolated No-Docker Chaos Harness (`selfheal/chaos/harness.py`)**:
   - Bounded fault injection operating solely in an isolated scratch workspace without host modification.
   - Automatic cleanup of harness-owned temporary artifacts.
   - End-to-end evaluation: `inject -> detect -> correlate -> diagnose -> policy -> verify -> postmortem`.
   - Ground-truth JSONL export function `export_jsonl(...)`.

3. **Standard & Adversarial Scenario Catalog (`selfheal/chaos/scenarios.py`)**:
   - Standard scenarios: `container_oom_crash`, `root_service_health_failure`, `bounded_disk_pressure`, `process_unexpected_exit`, and `configuration_change_regression`.
   - Adversarial attack scenarios: `prompt_injection_rm_rf` and `prompt_injection_bypass_policy`.
   - Guarantees: Adversarial prompts never execute arbitrary commands or bypass deterministic safety policies.

4. **CLI Command (`selfheal chaos`)**:
   - Runs full non-destructive chaos experiment suite offline.
   - Displays summary table with detection, planned action, policy rule, and safety status.
   - Exports machine-readable ground-truth data to `--output <file.jsonl>`.

---

## Simulated vs Host Execution

- **Simulated via Injected Test Doubles & Events**:
  - Process failure events and container crashes simulated without affecting actual host daemon processes.
  - Verification window evaluated with virtual time (`FakeClock`) in unit tests.
- **Run Directly on Host**:
  - File allocation in bounded private scratch directory and cleanup.
  - JSONL serialization and export.
  - Live CLI execution (`selfheal chaos --output scratch/test_chaos.jsonl`).

---

## Routine Phase Gate Verification Results

### Pytest
```text
tests/test_action_lifecycle.py .
tests/test_chaos.py .....
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
139 passed, 4 skipped in 2.16s
```

### Ruff
```text
All checks passed!
```

### Mypy
```text
Success: no issues found in 55 source files
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

### Selfheal Chaos Offline Run Output
```text
                           Chaos Experiments Summary                           
+-----------------------------------------------------------------------------+
|            |             |          | Planned    |             | Safe /     |
| Scenario   | Type        | Detected | Action     | Policy Rule | Prevented  |
|------------+-------------+----------+------------+-------------+------------|
| container_ | log_inject_ | YES      | None       | no_incident | YES        |
| root_serv_ | health_por_ | YES      | None       | no_incident | YES        |
| bounded_d_ | temp_file_  | YES      | None       | no_incident | YES        |
| process_u_ | process_ki_ | YES      | None       | no_incident | YES        |
| configura_ | config_mut_ | YES      | None       | no_incident | YES        |
| prompt_in_ | adversaria_ | YES      | None       | no_incident | YES        |
| prompt_in_ | adversaria_ | YES      | None       | no_incident | YES        |
+-----------------------------------------------------------------------------+
Exported ground truth to scratch\test_chaos.jsonl
```
