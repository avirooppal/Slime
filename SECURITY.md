# Slime security model

Monitoring is read-only with respect to targets. Typed execution is dry-run by default.
Local and optional cloud diagnosis are implemented, with all model outputs subject to
the same deterministic policy. Logs, labels, names, file contents
and probe responses are untrusted data, never instructions. Evidence cannot grant
approval, change configuration or mark a diagnosis trustworthy. Operator code,
inventory configuration and local database ownership are trusted.

## Deterministic authorization

The executor accepts registered action names and strict parameter schemas only,
never shell commands. Parameters select exact inventory aliases. Authorization
evaluates the kill switch first, then proposal/incident identity, registered action
and forbidden-action rules, parameter schemas, trusted diagnosis status, budget and
flapping checks, minimum confidence, the human-reset circuit breaker, live
inventory identity/revision, critical-target and per-action (`enabled_actions`)
human approvals, blast radius, dry-run, cooldown, hourly budget, and live action
preconditions. Refusals and authorizations are audited; unavailable audit/state
storage fails closed. Live state is rechecked before dispatch.

Approved defaults: `enabled_actions: []` (no action auto-executes until explicitly
enabled via `selfheal enable-action`), confidence 0.90, one automatic target, five
automatic attempts per hour, 300-second cooldown, breaker after three consecutive
failed fixes, and 120-second sampled health stability. Failed attempts consume the
budget. Exact, expiring, single-use approvals cover critical targets, non-enabled
actions, and APPROVAL actions. When more than one proposal is staged, `selfheal approve <incident_id>`
refuses and lists all staged proposals with their SHA-256 digests, requiring
`selfheal approve <digest>`. Approvals do not bypass kill switch, invalid output,
confidence, dry-run or breaker rules. Human control APIs are a trusted local
boundary, not an authentication service.

The closed remediation registry contains 8 mutation actions (`restart_container`,
`restart_managed_process`, `clear_tmp_files`, `rotate_logs`, `restart_service`,
`kill_runaway_process`, `reload_nginx`, `rollback_to_previous_image`).
SAFE container restart requires a crashed target and actual health verification.
SAFE managed-process restart is limited to a service with an operator-configured
absolute executable, working directory and fixed argument list. Slime starts
that child itself and records its PID and birth time; it cannot adopt an
unrelated PID. A healthy configured endpoint with no matching owned PID blocks a
duplicate start. The executable and directory must be regular/non-symlink targets
in the configured inventory. Immediately before spawn Slime rechecks the exact
owned-process state and file metadata. It never kills an already running but
unhealthy process. The child gets a minimal environment (Windows SystemRoot
only; empty on POSIX) to avoid inheriting Slime's cloud key. Startup readiness
has a bounded optional grace period; stability verification then checks the
configured HTTP/TCP probe, or liveness alone if none exists. There is no generic
rollback after spawn, so a failed verification escalates and the owned child
may remain running. An operator with write access to the configured executable
or directory could race path validation and launch; protect these paths with OS
permissions. SQLite ownership records also rely on protected local DB access.
Service restart/reload and process termination require approval. Image rollback
is refused by the native backend until a trusted deployment-specific adapter can
preserve its deployment configuration. `free_docker_space` has been removed from
the action registry; no Docker prune/image-removal, arbitrary deletion, DB
mutation, firewall or package action exists.

File mutations are disabled unless exact private POSIX files are explicitly
attested quiescent and free of secrets. Cleanup quarantines one file and retains
its contents; it does not reclaim capacity. Rotation preserves the original and
refuses rollback if new log contents would be lost. Windows native file mutations
are disabled. No recursive file action or live-writer rotation is implemented.

Pending executions survive restart and block further repairs until a human
reconciles them. Verification failure permits at most one supported safe rollback,
then escalation. A failed resolution write after verified recovery activates the
kill switch without undoing recovery. Stop guards run immediately before native
mutations. A kill switch cannot undo an operation already accepted by Docker or
systemd; separate processes see persisted controls at their next guard. The same
process verifier wakes through its stop event. Stability samples cannot prove
health between probes. UTC rate-limit/approval timestamps trust the host clock.

## Diagnostic and injection boundaries

Diagnostics have a separate immutable registry of 10 read-only tools (`tail_logs`,
`get_container_status`, `check_port`, `disk_usage`, `top_processes`,
`recent_changes`, `diff_config`, `http_probe`, `dns_check`, and
`rerun_healthcheck`) and no action dispatch capability. Because `rerun_healthcheck`
is a read-only diagnostic tool rather than a remediation action, it consumes no
cooldown or hourly mutation budget.
Only configured services, PIDs, exact files and endpoints are accessible. Path
validation rejects traversal, symlinks and Windows reparse points; POSIX reads
walk pinned directory descriptors with no-follow, and Windows validates the
opened handle before reading. HTTP follows no redirects or ambient proxies and
returns status only. Config diffs use a bounded redacted in-memory baseline.
Subprocesses use argument lists, bounded pipes and deadlines, never shell=True.

Every tool output is truncated, redacted and JSON-escaped inside an UNTRUSTED_DATA
block. Fake closing delimiters cannot escape this block. Tests cover fake JSON,
fake tools, malicious names, oversized inputs and Unicode/control tricks. The
deterministic gate rejects injected actions independent of any prompt. D3 prompt
and model-loop adversarial tests exercise these boundaries. Delimiters alone are
not a guarantee against model persuasion; the typed policy is the final gate.

Read-only workers have caller deadlines and admit no replacement worker while
one remains stuck; late output is discarded. Native subprocesses have their own
deadlines. Python threads cannot forcibly cancel an uninterruptible OS/library
read. Monitoring is not an OS sandbox against a hostile privileged local user.

Optional Docker uses fixed local UNIX/named-pipe endpoints, ignores DOCKER_HOST
and disables ambient HTTP proxy/netrc use before network requests. SDK 7's
constructor otherwise loads credential configuration, so a scoped, locked
compatibility shim supplies an empty auth configuration during construction.
This depends on an SDK-private helper: the extra is restricted to major version 7
and unfamiliar/failing SDKs degrade with one warning, never a credential-reading
fallback. The actual SDK constructor is tested with network and credential access
mocked. See the [SDK constructor source](https://raw.githubusercontent.com/docker/docker-py/main/docker/api/client.py).

## Evidence, secrets and cloud

Evidence strips control/format characters, truncates input and redacts common
credential assignments, quoted values, bearer tokens, sk-prefixed keys, emails
and IPv4 addresses into stable SHA-256 placeholders. Stored log evidence is the
sanitized template without extracted parameters. Event strings, audit reasons,
actor labels and recovery metadata are recursively sanitized. Config contents
are hashed rather than stored. Never put credentials in configuration, names,
paths or endpoint URLs.

### Cloud boundary
- Configuration models enforce a strict `@model_validator(mode="before")` that
  rejects any mapping key or value containing `api_key`, `secret`, `token`, `password`,
  `sk-`, `ghp_`, or private key blocks.
- Only `SLIME_CLOUD_API_KEY` is read from the process environment. It is never
  put in configuration or the event database.
- The D4 adapter sends service aliases, hashed template IDs and abstract signal
  types to the explicitly configured HTTPS endpoint. Raw logs and file contents
  are excluded from the outbound message. Every reserved call stores the exact
  outbound payload and byte count in SQLite audit data.
- A monthly call and estimated-spend reservation is persisted before each request;
  an hourly call cap also applies. The cost is a configured worst-case *estimate*:
  the provider can bill differently. Use provider-side limits for a hard bill cap.
- Redaction is best effort. Secrets embedded in unrecognized metric labels or
  unusual encodings can still leak context; do not enable cloud for sensitive
  inventories without reviewing the abstract outbound schema.

### Dashboard and notification boundaries
- The FastAPI dashboard binds strictly to `127.0.0.1` (`localhost`).
- Binding to `0.0.0.0` or external network interfaces is rejected with a fatal error.
- A custom Starlette middleware verifies incoming client IP addresses, immediately
  returning HTTP 403 Forbidden for non-localhost clients.
- Each dashboard start generates an in-memory random token printed to the local
  terminal. POST approvals require that token, same-origin and Host validation,
  a staged proposal digest, an active incident and a fresh policy evaluation.
  The token is absent from configuration and SQLite; local users who can read
  the terminal or browser session can authorize approval-tier actions.
- Multi-channel notifications (desktop toasts, loggers) run in non-blocking try/except
  guards with sanitized arguments and timeouts, ensuring notification failures never
  delay or interrupt remediation actions.

SQLite triggers reject ordinary UPDATE/DELETE of audit rows. A user with DB write
access can replace the file or schema: append-only is an application invariant,
not tamper-evident storage. Drain3 serializes internal state through jsonpickle;
protect database ownership and never load an untrusted database. The YAML
inventory and adapters must also remain operator-controlled.

