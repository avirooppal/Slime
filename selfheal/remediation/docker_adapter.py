"""Lazy local Docker SDK adapter; image deletion is one exact dangling ID at a time."""

import importlib
import os
import re
import threading
from typing import Any
from unittest.mock import patch

from selfheal.collectors.common import Warnings

BOOTSTRAP_LOCK = threading.Lock()


def credential_free_client(module: Any, base_url: str) -> Any:
    """Isolate SDK 7 constructor config and disable ambient auth/proxies before IO."""
    # SDK 7 has no public option to disable loading Docker credential config.
    # Scope this compatibility shim to construction; unfamiliar SDKs fail closed.
    with (
        BOOTSTRAP_LOCK,
        patch("docker.api.client.config.load_general_config", side_effect=lambda: {"auths": {}}),
    ):
        minimum = module.constants.MINIMUM_DOCKER_API_VERSION
        if not isinstance(minimum, str) or not re.fullmatch(r"\d{1,3}\.\d{1,3}", minimum):
            raise RuntimeError("unsupported Docker SDK bootstrap version")
        probe = module.DockerClient(base_url=base_url, timeout=3, version=minimum)
        try:
            probe.api.trust_env = False
            version = probe.api.version(api_version=False)["ApiVersion"]
            if not isinstance(version, str) or not re.fullmatch(r"\d{1,3}\.\d{1,3}", version):
                raise RuntimeError("invalid local Docker API version")
        finally:
            probe.close()
        client = module.DockerClient(base_url=base_url, timeout=3, version=version)
        client.api.trust_env = False
        return client


class DockerAdapter:
    """Optional Docker access never reads DOCKER_HOST or cloud credentials."""

    def __init__(self) -> None:
        """Delay importing/connecting until an explicitly configured target needs it."""
        self._client: Any = None
        self.warnings = Warnings()

    def client(self) -> Any:
        """Connect only to the local Unix socket or Windows named pipe."""
        if self._client is None:
            try:
                module = importlib.import_module("docker")
                base_url = (
                    "unix:///var/run/docker.sock"
                    if os.name == "posix"
                    else "npipe:////./pipe/docker_engine"
                )
                self._client = credential_free_client(module, base_url)
                self._client.ping()
            except Exception:  # noqa: BLE001 - optional SDK failures must degrade gracefully
                self._client = None
                self.warnings.warn("docker", "SDK missing or local daemon unavailable")
                raise RuntimeError("optional Docker unavailable") from None
        return self._client

    def container(self, configured_name: str) -> Any:
        """Resolve only the name already authorized by native inventory."""
        container = self.client().containers.get(configured_name)
        container.reload()
        return container

    def image(self, image_id: str) -> Any:
        """Load an operator-configured immutable image ID."""
        return self.client().images.get(image_id)

    def dangling(self, image_id: str) -> bool:
        """Require the exact image to be dangling and not referenced by containers."""
        matches = self.client().images.list(filters={"dangling": True})
        if not any(image.id == image_id for image in matches):
            return False
        return not self.client().containers.list(all=True, filters={"ancestor": image_id})
