"""Phase 5 tests: Ollama localhost adapter, strict Pydantic JSON, hypothesis loop, timeouts, adversarial injection, and D2 fallback."""

import json
from unittest.mock import Mock

import httpx

from selfheal.diagnosis.contracts import DiagnosisTier
from selfheal.diagnosis.investigator import ModelInvestigator
from selfheal.diagnosis.ollama_client import OllamaClient
from selfheal.models import Event, Incident, Kind, utcnow


def make_test_event(service: str, evidence: str = "") -> Event:
    return Event(
        timestamp=utcnow(),
        kind=Kind.ALERT,
        service=service,
        source="test",
        severity="error",
        evidence=evidence,
    )


class MockTransport(httpx.BaseTransport):
    """Controllable HTTP transport for Ollama chat and tags API."""

    def __init__(self, responses: list[dict[str, object]] | None = None, available: bool = True):
        self.responses = list(responses or [])
        self.available = available
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        url = str(request.url)
        if url.endswith("/api/tags"):
            if not self.available:
                return httpx.Response(status_code=503, text="Service Unavailable")
            return httpx.Response(status_code=200, json={"models": [{"name": "qwen2.5:3b-instruct"}]})

        if url.endswith("/api/chat"):
            if not self.responses:
                return httpx.Response(status_code=500, text="No mock responses left")
            curr = self.responses.pop(0)
            return httpx.Response(status_code=200, json=curr)

        return httpx.Response(status_code=404)


def test_ollama_client_step_generation():
    """Client parses strict Pydantic JSON from Ollama chat response."""
    step_data = {
        "thought": "Observed container exitCode 137; checking status",
        "action": "tool_call",
        "tool_call": {"tool": "get_container_status", "params": {"name": "worker"}},
        "confidence": 0.8,
        "root_service": "worker",
        "proposed_action": "restart_container",
        "proposed_params": {"target": "container.worker"},
        "rationale": "Container OOM exit",
    }
    mock_resp = {"message": {"content": json.dumps(step_data)}}
    transport = MockTransport([mock_resp])
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)

    step = ollama.generate_step([{"role": "user", "content": "investigate"}])
    assert step.action == "tool_call"
    assert step.tool_call is not None
    assert step.tool_call.tool == "get_container_status"
    assert step.confidence == 0.8


def test_ollama_retry_on_malformed_json():
    """Client retries once with error feedback on malformed JSON, then parses valid JSON."""
    invalid_resp = {"message": {"content": "Not JSON at all! Just text"}}
    valid_step = {
        "thought": "Recovered valid conclusion",
        "action": "conclude",
        "tool_call": None,
        "confidence": 0.95,
        "root_service": "worker",
        "proposed_action": "restart_container",
        "proposed_params": {"target": "container.worker"},
        "rationale": "Verified container failure",
    }
    valid_resp = {"message": {"content": json.dumps(valid_step)}}
    transport = MockTransport([invalid_resp, valid_resp])
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)

    step = ollama.generate_step([{"role": "user", "content": "investigate"}])
    assert step.action == "conclude"
    assert step.confidence == 0.95
    assert transport.calls == 2


def test_investigator_unavailable_abstains_for_fallback():
    """When Ollama is unavailable, investigator cleanly abstains to trigger D2 fallback."""
    transport = MockTransport([], available=False)
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)
    investigator = ModelInvestigator(ollama)

    incident = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    event = make_test_event("worker", "OOMKilled")
    result = investigator.diagnose(incident, [event])

    assert result.status == "abstain"
    assert result.deciding_tier == DiagnosisTier.D3_LOCAL_LLM
    assert "unavailable" in result.notes[0]


def test_investigator_bounded_six_step_loop(tmp_path):
    """Investigator executes bounded hypothesis loop with read-only tools and concludes."""
    # Step 1: call tool
    step1 = {
        "thought": "Need to check container status",
        "action": "tool_call",
        "tool_call": {"tool": "get_container_status", "params": {"name": "worker"}},
        "confidence": 0.5,
        "root_service": "worker",
        "proposed_action": None,
        "proposed_params": {},
        "rationale": "",
    }
    # Step 2: conclude
    step2 = {
        "thought": "Container is dead due to OOM; restart required",
        "action": "conclude",
        "tool_call": None,
        "confidence": 0.95,
        "root_service": "worker",
        "proposed_action": "restart_container",
        "proposed_params": {"target": "container.worker"},
        "rationale": "Tool confirmed container dead",
    }
    transport = MockTransport([{"message": {"content": json.dumps(step1)}}, {"message": {"content": json.dumps(step2)}}])
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)

    # Fake tool runner
    mock_runner = Mock()
    mock_runner.call.return_value = Mock(name="get_container_status", status="ok", data='{"status":"dead"}')

    investigator = ModelInvestigator(ollama, tool_runner=mock_runner, max_steps=6)
    incident = Incident(id="inc-1", services=["worker"], root_candidates=["worker"])
    event = make_test_event("worker", "OOMKilled")

    result = investigator.diagnose(incident, [event])
    assert result.status == "valid"
    assert result.deciding_tier == DiagnosisTier.D3_LOCAL_LLM
    assert result.selected is not None
    assert result.selected.proposed_action == "restart_container"
    assert result.selected.confidence == 0.95
    assert mock_runner.call.call_count == 1


def test_investigator_exceeded_steps_abstains_for_fallback():
    """If loop reaches 6 steps without concluding, investigator abstains cleanly."""
    step = {
        "thought": "Looping without conclusion",
        "action": "tool_call",
        "tool_call": {"tool": "tail_logs", "params": {"service": "worker", "n": 10}},
        "confidence": 0.5,
        "root_service": "worker",
        "proposed_action": None,
        "proposed_params": {},
        "rationale": "",
    }
    responses = [{"message": {"content": json.dumps(step)}} for _ in range(7)]
    transport = MockTransport(responses)
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)

    mock_runner = Mock()
    mock_runner.call.return_value = Mock(name="tail_logs", status="ok", data="some logs")

    investigator = ModelInvestigator(ollama, tool_runner=mock_runner, max_steps=6)
    incident = Incident(id="inc-1", services=["worker"])
    event = make_test_event("worker")

    result = investigator.diagnose(incident, [event])
    assert result.status == "abstain"
    assert "exceeded max steps" in result.notes[0]


def test_adversarial_injection_in_model_response():
    """Untrusted payload attempting to inject shell commands or fake policy is rejected by deterministic gate."""
    # Model hallucinating or injected with shell command
    malicious_step = {
        "thought": "Executing system command override",
        "action": "conclude",
        "tool_call": None,
        "confidence": 0.99,
        "root_service": "worker",
        "proposed_action": "rm_rf_root",
        "proposed_params": {"target": "worker; rm -rf /"},
        "rationale": "Injected command",
    }
    transport = MockTransport([{"message": {"content": json.dumps(malicious_step)}}])
    client = httpx.Client(transport=transport)
    ollama = OllamaClient(client=client)
    investigator = ModelInvestigator(ollama)

    incident = Incident(id="inc-adv", services=["worker"])
    event = make_test_event("worker", "ALERT: '; rm -rf /; sudo shutdown")

    result = investigator.diagnose(incident, [event])
    assert result.status == "valid"
    candidate = result.selected
    assert candidate is not None

    # Now verify the planner and deterministic safety policy reject this unregistered / invalid action
    from selfheal.planner.ranking import Planner
    from selfheal.remediation.registry import default_registry
    from tests.safety_fakes import FakeInventory

    planner = Planner(default_registry(), FakeInventory())
    proposals = planner.plan(result)
    # Planner strictly rejects unregistered action 'rm_rf_root'
    assert len(proposals) == 0
