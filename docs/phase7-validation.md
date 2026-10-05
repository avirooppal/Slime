# Phase 7 Validation: Reproducible Benchmarking & Dataset Adapters

## Overview
Phase 7 implements reproducible incident benchmarking, standard tier metrics reporting (detection, diagnosis, repair, false-positive, unsafe-attempt rates, and latency), public dataset adapters with honest documentation, and the `selfheal bench` CLI command from the original phase plan.

## Implemented Components
1. **Benchmark Contracts (`selfheal/eval/contracts.py`)**:
   - `TierMetrics`: Typed metrics model per tier capturing total scenarios, detection rate, diagnosis accuracy, repair success rate, false-positive rate, unsafe attempt count & rate, and mean latency in milliseconds.
   - `BenchmarkReport`: Structured report aggregating per-tier metrics, overall system performance, dataset availability, licensing, and environment metadata.

2. **Dataset Adapters (`selfheal/eval/dataset_adapters.py`)**:
   - `DatasetAdapter`: Abstract base class enforcing dataset naming, licensing, local availability checking, typed scenario loading, and honest documentation.
   - `LocalCatalogAdapter`: Evaluates local synthetic and adversarial failure scenarios from Phase 4 (Apache-2.0, 100% locally available and reproducible).
   - `TrainTicketAdapter`: Documents the public Train-Ticket microservice benchmark traces (Apache-2.0); checks local presence without inventing fake traces or unverified SOTA claims.
   - `AIOpsChallengeAdapter`: Documents the academic AIOps challenge dataset; honestly reports when upstream academic registration/traces are not present locally.

3. **Benchmark Runner (`selfheal/eval/runner.py`)**:
   - `BenchmarkRunner`: Evaluates scenarios in isolated in-memory stores and correlators across configured tiers (`D2_RUNBOOK`, `COMBINED`, etc.).
   - Guarantees safety invariants: validates that adversarial injection scenarios strictly result in 0 unsafe actions (`unsafe_attempts == 0`).
   - Measures exact detection rates, diagnosis accuracy, repair proposals, and latency.

4. **CLI Command (`selfheal bench` in `selfheal/interface/cli.py`)**:
   - Formatted Rich table breakdown across evaluated tiers.
   - Optional `--json` flag and `--output <path>` export for structured evaluation results.
   - Configurable `--dataset` adapter selection (`local`, `train-ticket`, `aiops`) and `--tiers` selection.

## Phase Gate Verification Output

### Test Suite (`pytest -q -ra`)
```text
........................................................................ [ 44%]
........................................................................ [ 88%]
...................                                                      [100%]
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
159 passed, 4 skipped, 4 warnings in 6.99s
```

### Ruff Linter (`ruff check selfheal tests`)
```text
All checks passed!
```

### Mypy Static Type Checker (`mypy selfheal --ignore-missing-imports`)
```text
Success: no issues found in 66 source files
```

### Dependency Check (`pip check`)
```text
No broken requirements found.
```

### Live CLI Benchmark Execution (`selfheal bench`)
```text
Dataset: Slime Local Chaos Catalog (Apache-2.0)
Built-in synthetic and adversarial failure scenario catalog; 100% locally 
reproducible.
                                                                               
                         Benchmark Evaluation by Tier                          
+-----------------------------------------------------------------------------+
|            |       |         |   Diag |  Repair |     FP |  Unsafe | Latency|
| Tier       | Total | Detect  |    Acc |    Rate |   Rate |    Attr |   (ms) |
|------------+-------+---------+--------+---------+--------+---------+--------|
| D2_RUNBOOK |     7 |   71.4% |  60.0% |    0.0% |   0.0% |    0.0% |    7.2 |
| COMBINED   |     7 |   71.4% |  60.0% |    0.0% |   0.0% |    0.0% |  115.9 |
+-----------------------------------------------------------------------------+
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

## Safety Invariant Verification
- **Unsafe Attempt Rate**: Evaluated on adversarial scenarios (`prompt_injection_rm_rf`, `prompt_injection_bypass_policy`). Invariant strictly maintained at **0.0%** across all tiers; prompt and command injections were completely blocked by policy.
- **Honest Dataset Documentation**: When public dataset traces (e.g. Train-Ticket, AIOps Challenge) are absent, the adapters report absence honestly; no simulated or invented dataset results are claimed.
