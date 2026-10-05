# Phase 6 Validation: Learning from Verified Repair Outcomes

## Overview
Phase 6 implements historical repair learning with canonical context fingerprinting, sample thresholding, drift detection, and strict safety gates from the original phase plan.

## Implemented Components
1. **Context Fingerprinting (`selfheal/learning/contracts.py`, `selfheal/learning/fingerprint.py`)**:
   - `ContextFingerprint`: Canonical multi-attribute model capturing primary service, involved services, root cause candidates, downstream topology, Drain3 template IDs, metric signatures, change signatures, and event kinds.
   - Deterministic SHA-256 fingerprint hash based on canonical sorted JSON serialization.
   - Multi-dimensional weighted Jaccard similarity across topology (0.35), templates (0.35), metrics (0.15), and changes (0.15).
   - Context drift and shift detection (`detect_shift`): identifies root cause candidate mismatch, primary service mismatch, conflicting metric pressures (e.g., disk full vs CPU spike), severe error template divergence, and system change context shifts.

2. **Learning Engine & Safety Invariants (`selfheal/learning/engine.py`)**:
   - `LearningEngine`: Coordinates outcome recording and shortcut evaluations.
   - **"No failed/unstable outcome counts as success"**:
     - Outcomes are recorded as `stable=True` strictly when execution succeeds and stability verification passes.
     - Failed executions or unstable verifications are recorded with `stable=False`.
     - Any historical failure or unstable outcome for an action/target blocks shortcutting and forces full diagnosis.
   - **Minimum sample count**: Requires at least `min_samples` (default: 2, configurable) verified stable outcomes before allowing past fixes to shorten diagnosis.
   - **Similarity threshold**: Requires multi-attribute similarity >= `similarity_threshold` (default: 0.85, configurable).
   - **"Context shift forces full diagnosis"**: Any detected symptom, metric, or topological drift overrides shortcutting and triggers full multi-step investigation.

3. **Storage Migrations (`selfheal/storage/store.py`)**:
   - Additive SQLite column `fingerprint TEXT` in `verified_outcomes`.
   - Preserves existing schemas, indexes, and write-boundary triggers.
   - Stores rich serialized context fingerprints and execution statuses.

4. **Runtime Coordinator Integration (`selfheal/runtime.py`)**:
   - Evaluates learning shortcut at the start of `diagnose_incident`.
   - If shortcut criteria are met: immediately shortens diagnosis with calibrated high confidence (D1_MEMORY).
   - If shortcut criteria are not met (cold start, sample count < min_samples, failure history, or context shift): forces full diagnosis via D3 local LLM (Ollama) and D2 declarative runbooks.
   - Records all executed remediation outcomes (successes and failures) with fingerprints in SQLite.

## Phase Gate Verification Output

### Test Suite (`pytest -q -ra`)
```text
........................................................................ [ 46%]
........................................................................ [ 92%]
............                                                             [100%]
============================== warnings summary ===============================
tests/test_chaos.py::test_temp_file_fill_bounded_and_cleaned
tests/test_chaos.py::test_container_crash_scenario_lifecycle
tests/test_chaos.py::test_adversarial_injection_never_executes_unsafe_actions
tests/test_chaos.py::test_ground_truth_jsonl_export
  C:\Users\aviroop\Desktop\Slime\selfheal\runtime.py:79: UserWarning: journald unavailable: journalctl missing; remaining collectors continue
    self.warnings.warn("journald", "journalctl missing")

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ===========================
SKIPPED [1] tests\test_collectors.py:65: host requires symlink privileges
SKIPPED [2] tests\test_native_actions.py:143: native file mutation requires POSIX directory APIs
SKIPPED [1] tests\test_native_actions.py:165: native file mutation requires POSIX directory APIs
152 passed, 4 skipped, 4 warnings in 4.07s
```

### Ruff Linter (`ruff check selfheal tests`)
```text
All checks passed!
```

### Mypy Static Type Checker (`mypy selfheal --ignore-missing-imports`)
```text
Success: no issues found in 63 source files
```

### Dependency Check (`pip check`)
```text
No broken requirements found.
```

### System Doctor (`selfheal doctor`)
```text
+-----------------------------------------------------------------------------+
| Component          | Status            | Reason                             |
|--------------------+-------------------+------------------------------------|
| Host metrics       | active            | psutil; aggregate only             |
| docker             | installed         | optional; not activated by the     |
|                    |                   | monitoring CLI                     |
| dashboard          | missing           | optional; not activated by the     |
|                    |                   | monitoring CLI                     |
| embed              | missing           | optional; not activated by the     |
|                    |                   | monitoring CLI                     |
| laya               | missing           | optional; not activated by the     |
|                    |                   | monitoring CLI                     |
| Ollama             | reachable         | qwen2.5:3b-instruct; D3 active in  |
|                    |                   | Phase 5                            |
| Diagnosis D1/D2/D3 | active            | D1 memory, D2 runbooks, and D3     |
|                    |                   | local LLM                          |
| D4/D5              | disabled          | Phase 8; optional cloud/Laya not   |
|                    |                   | implemented                        |
| Safety policy      | active            | deterministic; confidence >= 0.9   |
| Action registry    | 9 typed actions   | SAFE/APPROVAL; exact live          |
|                    |                   | inventory required                 |
| Execution          | dry-run (default) | runtime CLI wired in Phase 3       |
+-----------------------------------------------------------------------------+
```

## Simulated vs Host Aspects
- **Simulated in Tests**: Fast-path virtual time (`FakeClock`) was used to advance clock time across 300-second correlation and action cooldown windows without wall-clock sleeps. `FakeInventory` and `FakeBackend` were used for container state transitions and action execution tracking.
- **Run on Host**: Native psutil metric collectors, SQLite transactional storage and migrations, CLI commands (`selfheal doctor`), and Ollama localhost HTTP connectivity probing.
