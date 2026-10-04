"""D3 local LLM investigator running bounded hypothesis loop with tools."""

from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.diagnosis.ollama_client import OllamaClient
from selfheal.diagnosis.prompts import build_initial_user_prompt, build_tool_result_prompt
from selfheal.diagnosis.tools import ToolRunner
from selfheal.models import Event, Incident


class ModelInvestigator:
    """Bounded multi-step hypothesis tester using local Ollama model and read-only tools."""

    def __init__(
        self,
        client: OllamaClient,
        tool_runner: ToolRunner | None = None,
        max_steps: int = 6,
    ) -> None:
        """Initialize with Ollama client and optional tool runner."""
        self.client = client
        self.tool_runner = tool_runner
        self.max_steps = max_steps

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Run bounded investigation loop. If unavailable, invalid, or failing, abstain for D2 fallback."""
        if not self.client.is_available():
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                candidates=[],
                notes=["Ollama local LLM unavailable; fall back to D2 runbooks"],
            )

        events_summary: list[dict[str, object]] = [
            {
                "id": e.id,
                "kind": e.kind.value,
                "service": e.service,
                "severity": e.severity,
                "evidence": e.evidence[:256] if e.evidence else "",
                "template_id": e.template_id,
                "attributes": e.attributes,
            }
            for e in events[:20]
        ]

        messages = [
            {
                "role": "user",
                "content": build_initial_user_prompt(
                    incident.id, incident.services, incident.root_candidates, events_summary
                ),
            }
        ]

        notes: list[str] = []

        try:
            for step_num in range(1, self.max_steps + 1):
                try:
                    step = self.client.generate_step(messages)
                except Exception as e:  # noqa: BLE001 - parse or connection failures fall back cleanly
                    return DiagnosisResult(
                        incident_id=incident.id,
                        status="abstain",
                        deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                        candidates=[],
                        notes=[f"Model generation error at step {step_num}: {e}; fall back to D2"],
                    )

                if step.action == "abstain":
                    return DiagnosisResult(
                        incident_id=incident.id,
                        status="abstain",
                        deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                        candidates=[],
                        notes=[f"Model explicitly abstained: {step.thought}"],
                    )

                if step.action == "conclude":
                    root = step.root_service or (
                        incident.root_candidates[0]
                        if incident.root_candidates
                        else incident.services[0]
                    )
                    candidate = CandidateCause(
                        hypothesis=step.thought,
                        service=root,
                        confidence=step.confidence,
                        evidence_event_ids=[e.id for e in events[:5]],
                        tier=DiagnosisTier.D3_LOCAL_LLM,
                        proposed_action=step.proposed_action,
                        proposed_params=step.proposed_params,
                        rationale=step.rationale or step.thought,
                        blast_radius=1,
                    )
                    return DiagnosisResult(
                        incident_id=incident.id,
                        status="valid",
                        deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                        candidates=[candidate],
                        notes=[f"D3 concluded at step {step_num}"],
                    )

                if step.action == "tool_call":
                    if not step.tool_call or not self.tool_runner:
                        notes.append(f"Step {step_num}: requested tool call but tools unavailable")
                        continue

                    # Execute read-only tool
                    t_res = self.tool_runner.call(step.tool_call.tool, step.tool_call.params)
                    tool_prompt = build_tool_result_prompt(
                        step_num, str(t_res.name), str(t_res.status), str(t_res.data)
                    )
                    messages.append({"role": "assistant", "content": step.model_dump_json()})
                    messages.append({"role": "user", "content": tool_prompt})

            # Exhausted max steps without conclusion
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                candidates=[],
                notes=["D3 exceeded max steps without concluding; fall back to D2"],
            )

        except Exception as e:  # noqa: BLE001 - any uncaught loop exception falls back
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D3_LOCAL_LLM,
                candidates=[],
                notes=[f"D3 unexpected failure: {e}; fall back to D2"],
            )
