"""Client adapter for Ollama over localhost with strict per-step deadlines."""

import json
from typing import Any

import httpx

from selfheal.diagnosis.model_contracts import ModelHypothesisStep
from selfheal.diagnosis.prompts import SYSTEM_PROMPT


class OllamaClient:
    """Bounded localhost HTTP client communicating with Ollama."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5:3b-instruct",
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        """Initialize client with deadline and explicit localhost base URL."""
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout, trust_env=False)

    def is_available(self) -> bool:
        """Check if local Ollama daemon is reachable and responding."""
        try:
            client = self._get_client()
            resp = client.get(f"{self.base_url}/api/tags")
            return resp.status_code == 200
        except (httpx.HTTPError, OSError):
            return False

    def generate_step(
        self, messages: list[dict[str, str]], retry: bool = True
    ) -> ModelHypothesisStep:
        """Send chat request to Ollama and parse strict Pydantic JSON."""
        full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1024},
        }

        try:
            client = self._get_client()
            response = client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            raw_content = data.get("message", {}).get("content", "")
            return self._parse_json(raw_content)
        except Exception as e:
            if retry:
                # One retry with explicit error feedback
                retry_messages = messages + [
                    {
                        "role": "user",
                        "content": f"Previous response failed validation: {e}. Output ONLY valid JSON matching the schema.",
                    }
                ]
                return self.generate_step(retry_messages, retry=False)
            raise

    @staticmethod
    def _parse_json(content: str) -> ModelHypothesisStep:
        """Extract and validate JSON content."""
        clean_content = content.strip()
        clean_content = clean_content.removeprefix("```json").removeprefix("```")
        clean_content = clean_content.removesuffix("```").strip()

        parsed = json.loads(clean_content)
        return ModelHypothesisStep.model_validate(parsed)
