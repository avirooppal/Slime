# Phase 1 contracts and Phase 2 safety design

Event: UUID, aware UTC timestamp, kind, service, source, severity, redacted evidence
(<=4096 chars), optional content-derived template ID, typed scalar attributes.
Incident: UUID, state, UTC times, service/event membership, graph root candidates,
downstream symptoms, notes and flap count. Lifecycle changes have timestamped audit
records with reasons. SQLite indexes events by service/time; incident_events records
membership. Later phase tables (hypotheses/actions/outcomes/postmortems) are deferred.

The safety engine will receive a validated action proposal, diagnosis provenance,
live inventory snapshot and operator policy. It will emit a structured decision
with the first rejecting rule plus audit record. Executor rechecks the snapshot
immediately before executing an argument list. Models never supply shell commands.
SAFE is still conditional on every gate. APPROVAL cannot be auto-executed; FORBIDDEN
cannot be approved. State changed since diagnosis means abort/re-diagnose. A crash
restart is eligible only after verifying it is actually crashed. Approved kills and
rollbacks need explicit target identity. Destructive tmp cleanup requires narrowly
authorized paths, age/ownership checks and race-resistant access. Precise policies
for these actions require operator confirmation before Phase 2 implementation.

Build sequence: 1 core; 2 safety; 3 rules/retrieval and runtime CLI; 4 chaos/data;
5 Ollama; 6 learning; 7 benchmarks; 8 cloud/Laya; 9 dashboard/docs. Each phase must
pass its tests before any next-phase implementation begins.

