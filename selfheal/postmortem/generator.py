"""Postmortem generation for resolved, escalated or mitigated incidents."""

from selfheal.diagnosis.contracts import DiagnosisResult
from selfheal.models import Event, Incident
from selfheal.remediation.executor import ExecutionResult


class PostmortemGenerator:
    """Generate structured markdown and machine-readable postmortems."""

    @staticmethod
    def generate(
        incident: Incident,
        events: list[Event],
        diagnosis: DiagnosisResult | None = None,
        execution_result: ExecutionResult | None = None,
    ) -> tuple[str, dict[str, object]]:
        """Produce markdown report and structured data dictionary."""
        lines: list[str] = [
            f"# Incident Postmortem: {incident.id}",
            "",
            "## Summary",
            f"- **Status**: `{incident.state.value}`",
            f"- **Opened At (UTC)**: `{incident.opened_at.isoformat()}`",
            f"- **Updated At (UTC)**: `{incident.updated_at.isoformat()}`",
            f"- **Impacted Services**: {', '.join(f'`{s}`' for s in incident.services) or 'None'}",
            f"- **Root Candidates**: {', '.join(f'`{s}`' for s in incident.root_candidates) or 'None'}",
            f"- **Downstream Symptoms**: {', '.join(f'`{s}`' for s in incident.downstream) or 'None'}",
            f"- **Flap Count**: {incident.flap_count}",
            "",
        ]

        if incident.notes:
            lines.append("### Incident Notes")
            for note in incident.notes:
                lines.append(f"- {note}")
            lines.append("")

        lines.append("## Correlated Timeline & Evidence")
        if events:
            lines.append("| Time (UTC) | Kind | Service | Severity | Evidence / Reason |")
            lines.append("|---|---|---|---|---|")
            for e in events:
                reason = e.attributes.get("reason", "")
                detail = f"{e.evidence} {reason}".strip()
                if len(detail) > 80:
                    detail = detail[:77] + "..."
                detail = detail.replace("\n", " ").replace("|", "/")
                lines.append(
                    f"| {e.timestamp.strftime('%H:%M:%S')} | `{e.kind.value}` | `{e.service}` | `{e.severity}` | {detail} |"
                )
        else:
            lines.append("No recorded evidence events.")
        lines.append("")

        lines.append("## Diagnosis")
        if diagnosis:
            lines.append(f"- **Tier**: `{diagnosis.deciding_tier}`")
            lines.append(f"- **Status**: `{diagnosis.status}`")
            if diagnosis.notes:
                lines.append(f"- **Notes**: {'; '.join(diagnosis.notes)}")
            lines.append("")
            if diagnosis.candidates:
                lines.append("### Ranked Hypotheses")
                for i, c in enumerate(diagnosis.candidates, start=1):
                    lines.append(
                        f"{i}. **{c.hypothesis}** (Service: `{c.service}`, Confidence: {c.confidence:.2f})"
                    )
                    if c.proposed_action:
                        lines.append(f"   - Proposed Action: `{c.proposed_action}` ({c.proposed_params})")
                    if c.rationale:
                        lines.append(f"   - Rationale: {c.rationale}")
                    if c.evidence_event_ids:
                        lines.append(f"   - Evidence IDs: {', '.join(c.evidence_event_ids[:5])}")
                lines.append("")
        else:
            lines.append("No automated diagnosis performed.")
            lines.append("")

        lines.append("## Remediation & Verification")
        if execution_result:
            decision = execution_result.decision
            lines.append(f"- **Execution Status**: `{execution_result.status}`")
            lines.append(f"- **Policy Rule**: `{execution_result.rule}`")
            lines.append(f"- **Authorized**: `{decision.allowed}`")
            if decision.needs_human:
                lines.append("- **Human Approval / Review Required**: `True`")
            if decision.proposal:
                lines.append(
                    f"- **Executed Proposal**: `{decision.proposal.name}` on `{decision.proposal.params.get('target', 'unknown')}`"
                )
            if execution_result.verification:
                v = execution_result.verification
                lines.append(
                    f"- **Verification**: `{'Stable' if v.stable else 'Unstable'}` (Reason: `{v.reason}`, Elapsed: {v.elapsed_seconds:.1f}s)"
                )
            if execution_result.rolled_back:
                lines.append("- **Rollback Executed**: `True`")
        else:
            lines.append("No remediation action dispatched.")
        lines.append("")

        lines.append("## Prevention & Operator Actions")
        if incident.flap_count > 0:
            lines.append("- [ ] Investigate flapping root cause; automated repair did not prevent recurrence.")
        if execution_result and execution_result.status == "refused":
            lines.append(f"- [ ] Review policy refusal reason `{execution_result.rule}` and approve manually if appropriate.")
        elif execution_result and execution_result.status == "escalated":
            lines.append("- [ ] Inspect service health and logs manually; automated remediation failed verification.")
        else:
            lines.append("- [ ] Check long-term stability and review upstream dependencies.")
        lines.append("")

        payload: dict[str, object] = {
            "incident_id": incident.id,
            "status": incident.state.value,
            "services": incident.services,
            "roots": incident.root_candidates,
            "downstream": incident.downstream,
            "diagnosis_tier": diagnosis.deciding_tier if diagnosis else None,
            "execution_status": execution_result.status if execution_result else None,
            "execution_rule": execution_result.rule if execution_result else None,
            "verified_stable": execution_result.verification.stable if (execution_result and execution_result.verification) else None,
        }

        return "\n".join(lines), payload
