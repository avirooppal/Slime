# Slime security model (Phases 1–2)

Monitoring is read-only with respect to targets. Phase 2 adds separate typed
execution APIs; dry-run is true by default and the runtime repair CLI is Phase 3.
No LLM or cloud transport is implemented yet. Logs, labels, names, file contents
and probe responses are untrusted data, never instructions. Evidence cannot grant
approval, change configuration or mark a diagnosis trustworthy. Operator code,
inventory configuration and local database ownership are trusted.

## Deterministic authorization

The executor accepts registered action names and strict parameter schemas only,
never shell commands. Parameters select exact inventory aliases. Authorization
checks live identity/revision, trusted diagnosis status, confidence, critical
targets, blast radius, dry-run, kill switch, cooldown, hourly budget and the
human-reset circuit breaker. Refusals and authorizations are audited; unavailable
audit/state storage fails closed. Live state is rechecked before dispatch.

Approved defaults: confidence 0.90, one automatic target, five automatic attempts
per hour, 300-second cooldown, breaker after three consecutive failed fixes, and
120-second sampled health stability. Failed attempts consume the budget. Exact,
expiring, single-use approvals cover critical targets and APPROVAL actions.
Approvals do not bypass invalid output, confidence, kill, dry-run or breaker rules.
Human control APIs are a trusted local boundary, not an authentication service.

SAFE container restart requires a crashed target and actual health verification.
Service restart/reload, process termination and exact dangling-image removal
require approval. Image rollback is refused by the native backend until a trusted
deployment-specific adapter can preserve its deployment configuration. No broad
Docker prune, arbitrary deletion, DB mutation, firewall or package action exists.

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

Diagnostics have a separate immutable registry and no action dispatch capability.
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
templates and actual model-loop adversarial tests belong to Phase 5; delimiters
alone are not a guarantee against model persuasion.

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

### Zero-Secrets Invariant (Phase 8)
- Configuration models enforce a strict `@model_validator(mode="before")` that
  rejects any mapping key or value containing `api_key`, `secret`, `token`, `password`,
  `sk-`, `ghp_`, or private key blocks.
- Cloud API keys (`SLIME_CLOUD_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) must
  be supplied exclusively via process environment variables (`os.environ`).
- The D4 Cloud Investigator only transmits bounded, summary-level incident context
  pre-sanitized with `[REDACTED:<hash>]` tokens. Raw logs are never transmitted.
- Cloud invocations are bounded by hourly call limits and USD spend caps (`CloudBudget`),
  audited in SQLite, and degrade cleanly to local baselines on refusal or network failure.

### Dashboard & Notification Boundaries (Phase 9)
- The FastAPI dashboard binds strictly to `127.0.0.1` (`localhost`).
- Binding to `0.0.0.0` or external network interfaces is rejected with a fatal error.
- A custom Starlette middleware verifies incoming client IP addresses, immediately
  returning HTTP 403 Forbidden for non-localhost clients.
- Multi-channel notifications (desktop toasts, loggers) run in non-blocking try/except
  guards with sanitized arguments and timeouts, ensuring notification failures never
  delay or interrupt remediation actions.

SQLite triggers reject ordinary UPDATE/DELETE of audit rows. A user with DB write
access can replace the file or schema: append-only is an application invariant,
not tamper-evident storage. Drain3 serializes internal state through jsonpickle;
protect database ownership and never load an untrusted database. The YAML
inventory and adapters must also remain operator-controlled.

