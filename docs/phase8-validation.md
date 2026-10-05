# Phase 8 Validation: Optional Tiers (D4 Cloud LLM & D5 Laya Classifier)

## Overview
Phase 8 implements optional, opt-in advanced diagnosis tiers from the original phase plan:
1. **D4 Cloud LLM**: Opt-in external diagnosis via environment-only API keys, summary-only redaction (via `sanitize()`), strict hourly call/spend caps, and graceful 1-step degradation to local baselines.
2. **D5 Laya Classifier**: Opt-in fast closed-set neural/linear classifier with temperature-calibrated confidence, latency/confidence gating, feature ablation analysis, and graceful fallback.
3. **Strict Secrets Policy**: Invariant enforced across `Config` and `Store` ensuring API keys, secrets, tokens, or credentials never enter configuration files or database storage.

## Implemented Components
1. **Config Invariants & Safety Contracts (`selfheal/config.py`)**:
   - `cloud_enabled`, `cloud_provider`, `cloud_max_calls_per_hour`, `cloud_max_spend_usd`, `cloud_timeout_seconds`.
   - `laya_enabled`, `laya_confidence_threshold`, `laya_max_latency_ms`.
   - `@model_validator(mode="before") reject_secrets`: Strictly forbids any key containing `api_key`, `secret`, `token`, `password`, or values starting with `sk-`, `ghp_`, or private key blocks.

2. **D4 Cloud Contracts & Client (`selfheal/diagnosis/cloud_contracts.py`, `selfheal/diagnosis/cloud_client.py`)**:
   - `CloudBudget`: Enforces hourly call count caps and estimated USD spend caps before any network request is attempted.
   - `CloudSummaryRequest`: Structured incident summary strictly bounded and scrubbed via `sanitize()`. Raw credentials and tokens are redacted to `[REDACTED:<hash>]`.
   - `CloudInvestigator`:
     - Reads API keys strictly from `os.environ` (`SLIME_CLOUD_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`).
     - Audits every refusal, cap violation, or absent key to SQLite `audit_log`.
     - Degrades cleanly once to local baseline on network timeouts, HTTP errors, or absent keys without failing the pipeline.

3. **D5 Laya Contracts & Classifier (`selfheal/diagnosis/laya_contracts.py`, `selfheal/diagnosis/laya_classifier.py`)**:
   - `CLOSED_SET_CLASSES`: Closed set of DevOps root-cause categories (`container_crash`, `service_health_hang`, `process_crash`, `disk_pressure`, `config_regression`).
   - `LayaClassifier`:
     - Feature extraction across metric, template, health, process, and change signals.
     - Calibrated temperature scaling (`T = 1.25`) producing reliable probabilities.
     - Latency gating (`laya_max_latency_ms`) and confidence gating (`laya_confidence_threshold`).
     - Refusal/abstention on non-remediable classes (e.g. disk pressure where file quarantine does not reclaim capacity).
     - `run_ablation()`: Quantitative feature ablation ranking signal group importance.

4. **Coordinator Tier Hierarchy Integration (`selfheal/runtime.py`)**:
   - Integrated full tier hierarchy:
     1. D1 Memory Shortcut (if sample count and similarity gates pass)
     2. D5 Laya Classifier (if enabled, calibrated, and within latency threshold)
     3. D3 Local LLM (Ollama bounded hypothesis loop)
     4. D4 Cloud LLM (if enabled, within budget caps, and env key present)
     5. D2 Runbooks (deterministic local rules)
     6. D1 Raw BM25 Retriever / Safe Abstain

## Phase Gate Verification Output

### Test Suite (`pytest -q -ra`)
```text
........................s............................................... [ 42%]
..............................sss....................................... [ 84%]
..........................                                               [100%]
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
166 passed, 4 skipped, 4 warnings in 7.17s
```

### Ruff Linter (`ruff check selfheal tests`)
```text
All checks passed!
```

### Mypy Static Type Checker (`mypy selfheal --ignore-missing-imports`)
```text
Success: no issues found in 70 source files
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
|                    |                   | implemented / disabled by default  |
| Safety policy      | active            | deterministic; confidence >= 0.9   |
| Action registry    | 9 typed actions   | SAFE/APPROVAL; exact live          |
|                    |                   | inventory required                 |
| Execution          | dry-run (default) | runtime CLI wired in Phase 3       |
+-----------------------------------------------------------------------------+
```
