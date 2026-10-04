"""Explicit inventory and conservative monitoring configuration."""

import re
from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from selfheal.models import StrictModel
from selfheal.safety.contracts import SafetySettings


class Service(StrictModel):
    """An explicitly configured service and its read-only sources."""

    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    critical: bool = Field(default=False, strict=True)
    depends_on: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)
    configs: list[str] = Field(default_factory=list)
    journal_unit: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.@-]+$")
    process_pid: int | None = Field(default=None, gt=0)
    container_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    http_url: str | None = None
    tcp_host: str | None = None
    tcp_port: int | None = Field(default=None, ge=1, le=65535)


class Maintenance(StrictModel):
    """UTC or timezone-aware suppression interval for named services."""

    services: list[str]
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def valid_interval(self) -> "Maintenance":
        """Require unambiguous, increasing maintenance intervals."""
        if not self.start.tzinfo or not self.end.tzinfo or self.end <= self.start:
            raise ValueError("maintenance requires aware start < end")
        return self


class ManagedFileSettings(StrictModel):
    """No file mutation is enabled without explicit private-file attestations."""

    target: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    path: str
    kind: Literal["tmp_file", "log_file"]
    minimum_age_seconds: int = Field(ge=1)
    quiescent: bool = Field(default=False, strict=True)
    contains_secrets: bool = Field(default=True, strict=True)
    critical: bool = Field(default=False, strict=True)


class Config(StrictModel):
    """Local-only defaults; remediation remains opt-in and dry-run by default."""

    database: str = "slime.db"
    dry_run: bool = Field(default=True, strict=True)
    services: list[Service] = Field(default_factory=list)
    metrics_enabled: bool = True
    disk_paths: list[str] = Field(default_factory=list)
    correlation_seconds: int = Field(default=300, ge=1, le=86400)
    maintenance: list[Maintenance] = Field(default_factory=list)
    poll_seconds: float = Field(default=5, ge=0.1)
    stability_seconds: int = Field(default=120, ge=1, strict=True)
    max_auto_targets: int = Field(default=1, ge=1, strict=True)
    ollama_model: str = "qwen2.5:3b-instruct"
    learning_min_samples: int = Field(default=2, ge=1)
    learning_similarity_threshold: float = Field(default=0.85, ge=0.0, le=1.0)
    learning_enabled: bool = True
    cloud_enabled: bool = False
    cloud_model: str = "claude-3-5-sonnet-20241022"
    cloud_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    cloud_max_calls_per_hour: int = Field(default=10, ge=1, le=100)
    cloud_max_spend_usd: float = Field(default=5.0, ge=0.1)
    laya_enabled: bool = False
    laya_confidence_threshold: float = Field(default=0.85, ge=0.5, le=1.0)
    laya_max_latency_ms: float = Field(default=50.0, ge=1.0)
    safety: SafetySettings = Field(default_factory=SafetySettings)
    managed_files: list[ManagedFileSettings] = Field(default_factory=list)
    docker_images: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def reject_secrets(cls, data: object) -> object:
        """Reject any configuration containing API keys or secrets directly."""
        if isinstance(data, dict):
            for k, v in data.items():
                if any(sec in str(k).lower() for sec in ["api_key", "secret", "token", "password"]):
                    raise ValueError(f"Secrets forbidden in config: {k}. Use environment variables only.")
                if isinstance(v, str) and (v.startswith(("sk-", "ghp_")) or "BEGIN PRIVATE KEY" in v):
                    raise ValueError("Secrets forbidden in config values. Use environment variables only.")
        return data

    @model_validator(mode="after")
    def inventory(self) -> "Config":
        """Reject duplicate services, unknown dependencies and dependency cycles."""
        names = {s.name for s in self.services}
        if len(names) != len(self.services):
            raise ValueError("duplicate service")
        graph = {s.name: s.depends_on for s in self.services}

        def visit(name: str, trail: set[str]) -> None:
            """Validate dependencies recursively."""
            if name not in names or name in trail:
                raise ValueError("unknown dependency or dependency cycle")
            for dependency in graph[name]:
                visit(dependency, trail | {name})

        for name in names:
            visit(name, set())
        if any(name not in names for m in self.maintenance for name in m.services):
            raise ValueError("unknown maintenance service")
        for alias, image in self.docker_images.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", alias) or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", image
            ):
                raise ValueError("Docker image cleanup needs an alias and exact immutable digest")
        if self.safety.verification_timeout_seconds < self.stability_seconds:
            raise ValueError("verification timeout must cover stability window")
        return self


def load_config(path: Path) -> Config:
    """Read safe YAML and validate the complete configuration."""
    return Config.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
