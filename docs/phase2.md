# Phase 2: deterministic safety and bounded execution

Phase 1 was rerun before starting: 37 tests passed, one Windows symlink test was
skipped; Ruff, mypy, pip check and doctor passed. A real read-only poll collected
three host observations with no incidents. No repair was run against this host.

## Module boundaries

| Module | Responsibility |
|---|---|
| remediation/contracts.py, registry.py | Strict schemas, immutable risk tiers, lifecycle methods |
| safety/contracts.py, inventory.py | Untrusted proposals versus trusted context/live snapshots |
| safety/policy.py | Deterministic gates and auditable refusal rules |
| safety/state.py | SQLite reservations, approvals, cooldowns, caps, breaker, stop controls |
| safety/paths.py | Exact file allowlists, no-follow POSIX traversal, Windows opened-handle checks |
| remediation/executor.py | One attempt, immediate recheck, verification, rollback or escalation |
| verifier/stability.py | Healthy samples across the entire window; fail on a flap |
| diagnosis/tools.py, native_tools.py | Separate fixed read-only registry and bounded data envelopes |
| diagnosis/limits.py | Bounded read-only worker; never dispatches mutations |
| remediation/native_backend.py | Closed native dispatch with bounded argument-list commands |
| remediation/files.py | Single-file private-directory quarantine and reversible rotation |
| remediation/docker_adapter.py | Optional local Docker socket access, one warning on failure |

All adapters are injectable. Tests substitute live inventory, native effects and
clocks independently. The verifier's tests advance a full 120-second virtual
window; they do not weaken the production default or wait two minutes.

## Operator-approved defaults

Minimum confidence 0.90; five automatic authorizations per hour; 300-second
per-action/target cooldown; circuit opens after three consecutive failed attempts.
Only stable verified success resets the failure count. An open circuit requires
a human reset. Resolved/failed/aborted authorizations still consume their hourly
reservation budget; refusals without authorization do not.

Dry-run defaults true. One auto target at a time; one unresolved attempt globally
blocks subsequent repairs. Critical targets always require approval. All approvals
are exact-proposal/revision-bound, expire after five minutes by default, and are
consumed once. Trust status, operator approval and controls are never accepted from
the proposal JSON. Unknown fields, target aliases, commands and non-finite confidence
values are rejected. Proposal model instances are revalidated as well as raw dictionaries.

| Action | Tier | Native implementation and limits |
|---|---|---|
| restart_container | SAFE | Explicit configured alias; nonzero exit/OOM; application health required |
| restart_service | APPROVAL | Configured systemd unit; refuses a healthy service |
| clear_tmp_files | SAFE | One dedicated old quiescent regular file, private owned POSIX directory; quarantine |
| rotate_logs | SAFE | Same restrictions; preserve original and create a private empty replacement |
| kill_runaway_process | APPROVAL | Configured PID plus creation time; terminate only; PID 1/self protected |
| free_docker_space | APPROVAL | One exact operator-configured dangling image; no force, broad prune, volumes or parents |
| reload_nginx | APPROVAL | Explicit nginx service/unit only; no arbitrary command |
| rerun_healthcheck | SAFE | Configured read-only health probes, no target mutation |
| rollback_to_previous_image | APPROVAL | Typed digest schema; native adapter deliberately unavailable |

Generic image rollback cannot safely infer mounts, network settings, deployment
ownership or credential handling. Supply a deployment-specific typed ActionBackend
that validates its configured prior image and owns its recovery contract. Its risk
stays APPROVAL and all policy gates remain mandatory. Restart/terminate/prune/reload
have no universally safe inverse; failed verification escalates rather than inventing
a rollback. Private file operations support rollback and preserve original contents.
Rotating active writers requires a service-aware typed reopen/rotation adapter;
native rotation intentionally requires the operator's quiescent-file attestation.

Quarantine on the same filesystem **does not free disk space**. It removes a stale
tmp pathname reversibly. Do not use it as a disk-capacity fix. Original artifacts
remain in the private directory for operator review; there is no automatic purge.
Native file mutations refuse on Windows because their POSIX no-follow directory
operations are unavailable. Read-only diagnostics support Windows handle checks.

## Integration API (Phase 3 adds runtime CLI wiring)

```python
from selfheal.config import Config
from selfheal.remediation.native_backend import NativeBackend
from selfheal.remediation.registry import default_registry
from selfheal.remediation.executor import Executor
from selfheal.safety.native_inventory import NativeInventory
from selfheal.safety.policy import Policy
from selfheal.safety.state import SafetyState
from selfheal.storage.store import Store
from selfheal.verifier.stability import StabilityVerifier

config = Config()  # dry-run true, no mutation targets configured
store = Store(config.database)
state = SafetyState(store)
inventory = NativeInventory(config)
policy = Policy(default_registry(), inventory, NativeBackend(inventory), state,
                config.safety, dry_run=config.dry_run, max_auto_targets=config.max_auto_targets)
executor = Executor(policy, StabilityVerifier(
    window_seconds=config.stability_seconds,
    interval_seconds=config.safety.verification_interval_seconds,
    timeout_seconds=config.safety.verification_timeout_seconds,
    wait=state.stop.wait,
))
# Call executor.run(proposal, trusted_context) only after diagnosis and planning.
# Do not expose SafetyState.approve/reset_circuit/kill_switch to any model tool.
store.close()
```

Approval/control APIs require a trusted human actor identity. They are not a
standalone authentication system; CLI/dashboard authentication is future work.
Caller code and operator configuration are trusted. No collector or diagnostic
output may be converted into an approval or reliable-diagnosis status.

On interruption, persisted reserved/executing/verifying records block new repairs.
A human must inspect the target, call reconcile_interrupted(action_id, actor),
and explicitly reset the circuit. Slime does not assume a process-crashed action
succeeded. Receipts contain redacted recovery metadata, never file contents.

Verification is sampled stability, not proof of health between samples. Each read
probe has a caller deadline; a stuck read admits no replacement worker on that
runner until it finishes. Late outputs are discarded. Native commands have their
own timeouts; a server-side Docker/systemd operation already submitted may outlive
its client deadline. Kill switches stop further dispatch, verification and rollback;
they cannot retroactively cancel a mutation already accepted by another service.
Use state.stop.wait for immediate same-process verifier wakeup. Separate processes
observe persisted controls at the next guard/probe; cross-process wakeup is future
runtime integration. Limit/approval expiry timestamps use the trusted host UTC clock.

## Diagnostics and injection defense

Nine fixed tools: tail_logs, get_container_status, check_port, disk_usage,
top_processes, recent_changes, diff_config, http_probe, dns_check. Parameters are
strictly validated. Files/endpoints/services must match explicit inventory. Tools
cannot select or execute action names. Process lists include configured PIDs only.
HTTP returns status only, follows no redirects and ignores ambient proxy settings.
DNS requires nslookup to enforce its deadline. Log tails support files, configured
journald units and optional configured containers. recent_changes opens SQLite in
read-only mode. Config diffs establish a bounded redacted in-memory baseline on first
call; no raw config snapshot is stored and changes before that baseline are unknown.

Outputs are truncated, redacted and wrapped in a JSON-bearing UNTRUSTED_DATA block.
Delimiter characters are escaped inside JSON, so fake closing tags/tool results
cannot exit the data boundary. This is structural defense, not a claim that an LLM
cannot be persuaded by data: there is no LLM yet. D3 system prompts and model-loop
adversarial tests are Phase 5; the action gate remains independent of that model.

Local tests exercise fake Docker/systemd, exact target identity, persistent limits,
expired/reused approvals, failed audit writes, adversarial payloads, timeouts,
rollback/escalation and a full incident lifecycle with virtual verification time.
POSIX native file tests are configured for Linux CI and are skipped on Windows;
no remote CI or real Docker/systemd deployment result is claimed.

Live inventory and precondition reads also have caller deadlines. Native backends
receive a trusted stop callback and check it immediately before each mutation.
If persistence fails after verified recovery, execution sets the kill switch and
reports failure without rolling back the healthy target. Docker SDK major 7 is
optional; a scoped constructor shim suppresses its implicit credential-file load,
and proxy/netrc handling is disabled before network requests. This private SDK
compatibility boundary fails closed and has an actual-SDK mocked-network test.
