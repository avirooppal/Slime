"""Closed read-only diagnostic registry, separately typed from remediation actions."""

import json
import queue
import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, Protocol

from pydantic import Field, ValidationError

from selfheal.collectors.common import Warnings
from selfheal.models import StrictModel
from selfheal.security import sanitize
from selfheal.storage.store import Store


class ServiceParams(StrictModel):
    """An inventory service name rather than a command or arbitrary selector."""

    service: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$", strict=True)


class TailParams(ServiceParams):
    """Small positive log tail request."""

    n: int = Field(default=50, ge=1, le=200, strict=True)


class ContainerParams(StrictModel):
    """A configured container alias, not an attacker-selected runtime name."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$", strict=True)


class PortParams(StrictModel):
    """A host/port pair that must exactly match a configured health endpoint."""

    host: str = Field(min_length=1, max_length=253, strict=True)
    port: int = Field(ge=1, le=65535, strict=True)


class DiskParams(StrictModel):
    """A disk path that must exactly match explicit inventory."""

    path: str = Field(min_length=1, max_length=1024, strict=True)


class ProcessParams(StrictModel):
    """Only explicitly configured process metadata is listed."""

    n: int = Field(default=5, ge=1, le=20, strict=True)


class ChangesParams(ServiceParams):
    """A bounded recent-change time window in seconds."""

    window: int = Field(default=300, ge=1, le=86400, strict=True)


class DiffParams(StrictModel):
    """Exact configured file spelling; no arbitrary file reads."""

    file: str = Field(min_length=1, max_length=1024, strict=True)


class HTTPParams(StrictModel):
    """Exact configured URL; arbitrary network destinations are denied."""

    url: str = Field(min_length=1, max_length=2048, strict=True)


class DNSParams(StrictModel):
    """A host already present in explicit configured endpoints."""

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$", strict=True)


@dataclass(frozen=True)
class ToolDefinition:
    """The registry fixes schema and read-only identity independently of the model."""

    name: str
    schema: type[StrictModel]


class DiagnosticBackend(Protocol):
    """Implementation contract contains only authorized, read-only diagnostics."""

    def read(self, name: str, params: StrictModel) -> str:
        """Authorize inventory parameters then perform one bounded diagnostic."""
        ...


class ToolResult(StrictModel):
    """Redacted, truncated output explicitly marked as attacker-controllable data."""

    name: str
    status: Literal["ok", "refused", "timeout", "error"]
    data: str = Field(default="", max_length=4096)

    def data_block(self) -> str:
        """Escape delimiter characters so payload text cannot end its data block."""
        payload = json.dumps({"trust": "UNTRUSTED_DATA", **self.model_dump()}, ensure_ascii=True)
        payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        return "<UNTRUSTED_DATA>\n" + payload + "\n</UNTRUSTED_DATA>"


def tool_registry() -> MappingProxyType[str, ToolDefinition]:
    """Exactly the nine read-only tools; no action names share this dispatch table."""
    definitions: list[tuple[str, type[StrictModel]]] = [
        ("tail_logs", TailParams),
        ("get_container_status", ContainerParams),
        ("check_port", PortParams),
        ("disk_usage", DiskParams),
        ("top_processes", ProcessParams),
        ("recent_changes", ChangesParams),
        ("diff_config", DiffParams),
        ("http_probe", HTTPParams),
        ("dns_check", DNSParams),
    ]
    return MappingProxyType({name: ToolDefinition(name, schema) for name, schema in definitions})


class ToolRunner:
    """One bounded diagnostic worker; timed-out work cannot accumulate new threads."""

    def __init__(
        self, backend: DiagnosticBackend, store: Store, timeout_seconds: float = 3
    ) -> None:
        """Use an explicit hard caller deadline and a single worker admission lock."""
        if not 0 < timeout_seconds <= 30:
            raise ValueError("tool timeout must be in (0, 30]")
        self.backend, self.store, self.timeout = backend, store, timeout_seconds
        self.registry = tool_registry()
        self.busy = threading.Lock()
        self.warnings = Warnings()

    def _result(
        self, name: str, status: Literal["ok", "refused", "timeout", "error"], data: str
    ) -> ToolResult:
        """Audit refusals/timeouts without leaking backend exceptions or secret input."""
        result = ToolResult(name=sanitize(name, 64), status=status, data=sanitize(data))
        with self.store.connection:
            self.store.audit("diagnostic", "tool_" + status, result.name)
        return result

    def call(self, name: str, raw_params: object) -> ToolResult:
        """Validate first, bound worker count, discard late outputs and redact results."""
        definition = self.registry.get(name)
        if definition is None:
            return self._result(name, "refused", "unknown read-only tool")
        try:
            params = definition.schema.model_validate(raw_params)
        except (ValidationError, ValueError, TypeError):
            return self._result(name, "refused", "invalid diagnostic parameters")
        if not self.busy.acquire(blocking=False):
            return self._result(name, "refused", "diagnostic worker busy after earlier request")
        output: queue.Queue[tuple[Literal["ok", "refused", "error"], str]] = queue.Queue(maxsize=1)

        def worker() -> None:
            """Only the fixed read-only backend runs; no actions can be dispatched."""
            try:
                output.put(("ok", sanitize(self.backend.read(name, params))))
            except (LookupError, ValueError):
                output.put(("refused", "target outside inventory or unauthorized path"))
            except Exception:  # noqa: BLE001 - isolate failures at the read-only adapter boundary
                output.put(("error", "diagnostic unavailable"))
            finally:
                self.busy.release()

        threading.Thread(target=worker, daemon=True).start()
        try:
            status, data = output.get(timeout=self.timeout)
        except queue.Empty:
            self.warnings.warn("diagnostic:" + name, "read-only deadline exhausted")
            return self._result(name, "timeout", "tool deadline exhausted; late result discarded")
        if status == "error":
            self.warnings.warn("diagnostic:" + name, "component unavailable")
        return self._result(name, status, data)
