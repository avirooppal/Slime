# Slime implementation handoff

Status: Phases 1 and 2 are implemented. Start with Phase 3. The authoritative
product requirements and phase order are in the original project brief; this
document records the current code and the next execution plan. Work strictly in
order. Do not begin a phase until the preceding phase's tests pass, and show the
test output at the end of each phase.

## Current baseline

Workspace: `C:\Users\aviroop\Desktop\Slime` (Windows, PowerShell). This directory
is **not a Git repository**. Python 3.10.0 is available at `.venv/Scripts/python`.
The package installs editable with `.venv/Scripts/python -m pip install -e ".[dev]"`;
the `selfheal` console script points to `selfheal.interface.cli:app`.

Phase 1 supplies explicit-source file/journald/metric/health/change collection,
Drain3 templates, statistical anomaly alerts, a SQLite event store and a dependency
aware incident correlator. `Monitor.poll()` in `selfheal/runtime.py` performs one
read-only cycle. `init` and `doctor` work. Runtime `run` is **not implemented**.

Phase 2 supplies nine registered typed actions, native inventory, a separate
read-only diagnostic tool registry, deterministic safety policy, durable approvals
and controls, an executor and sampled stability verification. These are APIs,
**not a working self-healing CLI**. `selfheal/interface/cli.py` only exposes
`init` and `doctor`. `selfheal/planner`, `triage` and `eval` have placeholders.
There is no D1 memory, D2 runbooks, investigator, cloud adapter, Laya, chaos
harness, benchmark or dashboard. The actual SDK-backed Docker action tests use
mocked network access; no real Docker/systemd action has been exercised.

Last completed verification, recorded in [phase2-validation.md](phase2-validation.md):

```text
Phase 1 gate before Phase 2: 37 passed, 1 skipped; Ruff/mypy/pip check passed.
Phase 2: 123 passed, 4 skipped in 2.12s
Ruff: All checks passed!
Mypy: Success: no issues found in 45 source files
pip check: No broken requirements found.
doctor: successful; live read-only poll: 3 observations, 0 incidents
```

The four skips are one Windows symlink-privilege case and three POSIX native
file-mutation cases. Linux CI is configured but was not run here. Recheck this
baseline before Phase 3 changes; investigate any regression before proceeding.
Do not report skipped native cases as passed.

Useful starting points:

| Concern | Code/document |
|---|---|
| Product setup and limits | `README.md`, `SECURITY.md`, `config.example.yaml` |
| Event and incident models | `selfheal/models.py`, `selfheal/storage/store.py` |
| Collection and correlation | `selfheal/runtime.py`, `selfheal/correlator/engine.py` |
| Safety contracts and policy | `selfheal/safety/contracts.py`, `selfheal/safety/policy.py` |
| Durable controls/approval | `selfheal/safety/state.py` |
| Action registry and executor | `selfheal/remediation/registry.py`, `selfheal/remediation/executor.py` |
| Native inventory and diagnostics | `selfheal/safety/native_inventory.py`, `selfheal/diagnosis/tools.py` |
| Verification | `selfheal/verifier/stability.py` |
| Phase 2 API wiring and limits | `docs/phase2.md` |

## Safety contract to preserve

All log text, labels, container names, file contents and tool outputs are untrusted
data. They cannot supply a trusted `DiagnosisContext`, approval, target identity,
command or inventory entry. Candidate actions must be registered names plus strict
parameters; the policy rereads live state and reserves authorization atomically.
`Executor.run()` is the only mutation coordinator. Every decision, including
refusal, must be audited. A failure of audit/state persistence must stop actions.
Verification must span the full stability window; no one-shot health check counts
as success. Do not retry a flapping incident. Keep calls to tools read-only and
bounded. Never dispatch a model-produced shell command.

The operator approved these defaults: dry-run on; minimum confidence 0.90; one
automatic target; five automatic attempts/hour; 300-second per-action/target
cooldown; breaker after three consecutive failed fixes with human reset; service
restart/reload and Docker image removal require approval. File cleanup/rotation
require exact dedicated, private, quiescent POSIX files without secrets and
preserve original bytes by quarantine. `clear_tmp_files` **does not free disk**.
Windows native file mutation is disabled. Generic image rollback has a typed
APPROVAL entry but its native adapter refuses; a deployment-specific adapter
would be required. Do not present either as a working disk-space/image-rollback fix.

Safety-relevant choices **not already specified or approved** must be put to the
user before implementation, as requested in the original brief. In particular,
Phase 3 must define which exact D2 rule evidence, independent corroboration and
confidence calibration can authorize an automatic repair, how a CLI human actor
is authenticated/bound to an approval, and how explicit `dry_run: false` becomes
an operator decision. Until resolved, build read-only diagnosis and suggestions;
keep the execution path dry-run. Do not infer reliable status from log/model text.

## Phase 3 — useful without an LLM

1. Add a small diagnosis contract that carries incident ID, ranked root-cause
   candidates, evidence event IDs, confidence, proposed registered action/params,
   deciding tier and an explicit abstain result. Make the trusted coordinator set
   `DiagnosisContext`; diagnosis output itself must not set it.
2. Implement D1 BM25 retrieval using only persisted **verified** incident outcomes.
   In a fresh install it must abstain cleanly because there are no outcomes yet.
   Index template IDs, service/dependency context, changes and metric patterns;
   return the matched context and historical success evidence, not a global fix
   frequency. Keep optional embeddings out of core Phase 3 behavior.
3. Implement D2 declarative runbooks for the requested signatures. Distinguish
   root failures from downstream 5xx/health symptoms using the dependency graph
   and recent change events. A disk >90% alert may diagnose pressure but must
   not propose the current quarantine action as capacity reclamation. Rules that
   lack safe evidence should abstain or request human review.
4. Implement the planner as a pure, typed ranking function: similar-context
   proven success × confidence ÷ blast radius, with least invasive root-cause
   preference. It must never create an unregistered action or bypass policy.
5. Wire one-process polling, correlation, diagnosis, planning, policy, executor
   and postmortem generation. Keep collector failures isolated. Store hypotheses,
   outcome records and postmortems via additive SQLite migrations; preserve the
   existing DB and audit triggers. Record SUCCESS only after stable verification.
6. Add `run`, `status`, `incidents`, `approve`, `dry-run`, `kill-switch` commands.
   `run` remains dry-run by default; show the policy rule, selected evidence and
   required approval in plain language. The approval interface must bind to an
   exact proposal/revision and trusted local actor. Expose human reconciliation
   and circuit reset safely because interrupted attempts block new repairs.
7. Cover retrieval cold start, root/downstream distinction, false-positive
   abstention, exact approval and changed revision, denial audit, dry-run, failed
   verification and postmortem contents with unit tests and one local integration
   path. Keep tests fast with virtual time and fake action backends.

Phase 3 exit gate: a no-LLM, no-Docker install can collect configured local
signals, explain an incident, propose or safely execute a policy-authorized fix,
verify it for the configured window, and generate a postmortem. All existing and
new tests, Ruff, mypy and `pip check` pass. Show real command output in a new
`docs/phase3-validation.md`; document what was simulated versus run on the host.

## Later phases, in required order

| Phase | Build | Required gate before the next phase |
|---|---|---|
| 4 Chaos + data | Isolated no-Docker process/temp-file harness plus optional Docker Compose scenarios; JSONL ground-truth export; end-to-end inject→detect→correlate→diagnose→policy→verify→postmortem. Avoid destructive host faults: fill only a bounded temp filesystem/file and kill only harness-owned processes. | Scenario labels are correct, adversarial scenarios do not execute unsafe actions, fast end-to-end test passes offline. Show test output. |
| 5 Local LLM | Ollama over localhost via `httpx`; strict system/data prompts; only Phase 2 read-only tools; bounded six-step hypothesis loop, per-step deadlines, strict Pydantic JSON, one retry then D2 fallback. | Unavailable/timeout/invalid/injected model outputs abstain or fall back; no untrusted text grants execution. Adversarial suite passes. Show test output. |
| 6 Learning | Store context fingerprints and verified outcomes; similarity threshold and minimum sample count before past fixes can shorten diagnosis. | No failed/unstable outcome counts as success; context shift forces full diagnosis. Show test output. |
| 7 Benchmarking | `selfheal bench` table + JSON for each enabled tier; report detection, diagnosis, repair, FP and unsafe-attempt metrics. Verify public dataset availability/license before writing adapters; document any unsupported adapter honestly. | No invented public benchmark results or state-of-the-art claim; local regression results reproducible. Show test output. |
| 8 Optional tiers | D4 opt-in cloud with summary-only redaction, env-only key, spend/call caps and audit; D5 opt-in Laya with trained/calibrated closed-set classifier, held-out accuracy/calibration/latency gate and ablation. | Both extras absent/failing degrade once and preserve local baseline; secrets never enter config/DB. Show test output. |
| 9 Polish | Optional one-page localhost-only FastAPI dashboard, approvals/history/tier/health; desktop/log notifications and complete quickstarts/docs/security notes. | Fresh lite install and configured profiles work as documented; full test, lint, typing, packaging and smoke checks pass. Show test output. |

## Routine phase gate

On Windows use the project virtual environment; on Linux use `.venv/bin/`.

```powershell
.venv/Scripts/python -m pytest -q -ra
.venv/Scripts/python -m ruff check selfheal tests
.venv/Scripts/python -m mypy selfheal --ignore-missing-imports
.venv/Scripts/python -m pip check
.venv/Scripts/selfheal doctor
```

Run a read-only `Monitor.poll()` when monitoring code changes. Use isolated DBs,
temp files, fake clocks and fake adapters for mutation tests. Do not run a real
repair on the operator's host as a smoke test. Record exact output and skips at
the end of each phase. Add a short validation record. Update `doctor` and README
capability claims as features actually become functional. Keep the original
Python 3.10+ and core-dependency constraints; optional extras must degrade with
one clear warning and leave the rest operating.

## Copyable successor brief

> Continue building Slime in `C:\Users\aviroop\Desktop\Slime`. Read
> `docs/HANDOFF.md`, `SECURITY.md`, `docs/phase2.md` and the current code before
> changing it. Phases 1–2 are complete; reverify their tests first. Implement
> Phase 3 only, in small typed modules, with the no-LLM diagnosis and CLI behavior
> described above. Ask the operator before any new safety-affecting assumption.
> Keep dry-run on until the execution/approval trust boundary is resolved. Preserve
> every deterministic safety gate and treat all collected content as untrusted.
> End the phase with exact pytest, Ruff, mypy and dependency-check output, a
> working offline demonstration, and `docs/phase3-validation.md`. Do not start
> Phase 4 until Phase 3 passes.
