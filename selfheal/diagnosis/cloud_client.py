"""Opt-in Cloud LLM client (D4) with summary-only redaction, spend caps, and graceful degradation."""

import json
import os
import re

import httpx

from selfheal.config import Config
from selfheal.diagnosis.cloud_contracts import (
    CloudBudget,
    CloudDiagnosisResponse,
    CloudSummaryRequest,
)
from selfheal.diagnosis.contracts import CandidateCause, DiagnosisResult, DiagnosisTier
from selfheal.models import Event, Incident, Kind, utcnow
from selfheal.security import sanitize
from selfheal.storage.store import Store


class CloudInvestigator:
    """Bounded, opt-in cloud incident investigator with strict redaction and spend caps."""

    def __init__(
        self,
        config: Config,
        store: Store,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.config = config
        self.store = store
        self.http_client = http_client
        self.budget = CloudBudget(
            max_calls_per_hour=config.cloud_max_calls_per_hour,
            max_spend_usd=config.cloud_max_spend_usd,
        )

    def _get_api_key(self) -> str | None:
        """Resolve API key strictly from environment. Secrets never enter config or database."""
        return (
            os.environ.get("SLIME_CLOUD_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )

    def build_summary_request(self, incident: Incident, events: list[Event]) -> CloudSummaryRequest:
        """Construct sanitized summary-only payload. Raw log streams and secrets are excluded."""
        template_ids = sorted({e.template_id for e in events if e.template_id})
        metrics = sorted(
            {
                str(e.attributes.get("metric"))
                for e in events
                if e.kind == Kind.METRIC and e.attributes and e.attributes.get("metric")
            }
        )
        changes = sorted(
            {
                str(e.attributes.get("change"))
                for e in events
                if e.kind == Kind.CHANGE and e.attributes and e.attributes.get("change")
            }
        )

        # Build heavily sanitized, bounded evidence summary
        summary_lines: list[str] = []
        for e in events[:5]:  # limit to top 5 signals
            redacted = sanitize(e.evidence[:256])
            summary_lines.append(f"[{e.service} {e.kind.value}] {redacted}")

        return CloudSummaryRequest(
            incident_id=incident.id,
            target_services=sorted(incident.services),
            root_candidates=sorted(incident.root_candidates),
            downstream=sorted(incident.downstream),
            template_ids=template_ids,
            metric_signatures=metrics,
            change_signatures=changes,
            redacted_evidence_summary="\n".join(summary_lines),
        )

    def diagnose(self, incident: Incident, events: list[Event]) -> DiagnosisResult:
        """Query cloud LLM using redacted summary. Gracefully degrades to local tiers on any issue."""
        if not self.config.cloud_enabled:
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D4_CLOUD_LLM,
                candidates=[],
                notes=["D4 Cloud LLM is disabled in configuration; degrading to local baseline"],
            )

        api_key = self._get_api_key()
        if not api_key:
            self.store.audit("cloud_investigator", "key_missing", "no cloud api key in environment")
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D4_CLOUD_LLM,
                candidates=[],
                notes=["D4 Cloud API key not found in environment (env-only); degrading to local baseline"],
            )

        # Check hourly call and spend caps
        current_hour = utcnow().strftime("%Y-%m-%d-%H")
        allowed, reason = self.budget.can_call(current_hour)
        if not allowed:
            self.store.audit("cloud_investigator", "budget_cap", reason)
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D4_CLOUD_LLM,
                candidates=[],
                notes=[f"D4 Cloud {reason}; degrading to local baseline"],
            )

        request_payload = self.build_summary_request(incident, events)

        # Dispatch cloud API request (mockable via http_client)
        prompt = (
            "You are a DevOps troubleshooting agent. Given the following REDACTED high-level incident summary, "
            "propose a registered typed remediation action and target.\n"
            f"Summary:\n{request_payload.model_dump_json(indent=2)}\n\n"
            "Respond ONLY with a valid JSON object matching this schema:\n"
            '{"hypothesis": str, "target_service": str, "confidence": float, "proposed_action": str, "proposed_target": str, "rationale": str, "blast_radius": int}'
        )

        try:
            client = self.http_client or httpx.Client(
                timeout=self.config.cloud_timeout_seconds,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            # Simulated endpoint / standard cloud completion URL
            response = client.post(
                "https://api.slime.cloud/v1/diagnose",
                json={"model": self.config.cloud_model, "prompt": prompt},
            )
            response.raise_for_status()
            data = response.json()

            raw_content = data.get("content") or data.get("response") or json.dumps(data)
            match = re.search(r"\{.*\}", str(raw_content), re.DOTALL)
            if not match:
                raise ValueError("No JSON found in cloud response")

            parsed = CloudDiagnosisResponse.model_validate_json(match.group(0))

            # Record call in budget and audit log
            self.budget.record_call(estimated_cost=0.02)
            self.store.audit(
                "cloud_investigator",
                "call_success",
                f"model={self.config.cloud_model}, action={parsed.proposed_action}",
            )

            candidate = CandidateCause(
                hypothesis=f"[Cloud {self.config.cloud_model}] {parsed.hypothesis}",
                service=parsed.target_service,
                confidence=round(parsed.confidence, 3),
                evidence_event_ids=[e.id for e in events[:5]],
                tier=DiagnosisTier.D4_CLOUD_LLM,
                proposed_action=parsed.proposed_action,
                proposed_params={"target": parsed.proposed_target},
                rationale=parsed.rationale,
                blast_radius=parsed.blast_radius,
            )

            return DiagnosisResult(
                incident_id=incident.id,
                status="valid",
                deciding_tier=DiagnosisTier.D4_CLOUD_LLM,
                candidates=[candidate],
                notes=[f"D4 Cloud diagnosis accepted from {self.config.cloud_model}"],
            )

        except Exception as e:  # noqa: BLE001
            # Graceful degradation: never crash coordinator, log/audit and degrade once
            self.store.audit("cloud_investigator", "call_failed", f"error={type(e).__name__}")
            return DiagnosisResult(
                incident_id=incident.id,
                status="abstain",
                deciding_tier=DiagnosisTier.D4_CLOUD_LLM,
                candidates=[],
                notes=[f"D4 Cloud call failed ({type(e).__name__}); degrading once to local baseline"],
            )
