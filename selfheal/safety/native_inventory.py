"""Explicit native targets and freshly probed action-relevant state."""

import os
import shutil

import psutil

from selfheal.collectors.common import command
from selfheal.collectors.health_checks import Health
from selfheal.config import Config, Service
from selfheal.remediation.docker_adapter import DockerAdapter
from selfheal.remediation.files import FileOperations, ManagedFile
from selfheal.safety.contracts import Snapshot
from selfheal.safety.inventory import revision
from selfheal.safety.paths import PathAccess


class NativeInventory:
    """No automatic discovery grants mutation authority; aliases come from config."""

    def __init__(
        self,
        config: Config,
        files: list[ManagedFile] | None = None,
        docker_images: dict[str, str] | None = None,
        docker: DockerAdapter | None = None,
    ) -> None:
        """Pin managed files and symbolic service/container/process aliases."""
        self.config = config
        self.services: dict[str, Service] = {}
        self.files = FileOperations(
            files
            if files is not None
            else [ManagedFile(**m.model_dump()) for m in config.managed_files]
        )
        self.docker_images = dict(
            docker_images if docker_images is not None else config.docker_images
        )
        self.docker = docker or DockerAdapter()
        for service in config.services:
            if service.name.startswith(("container.", "process.")):
                raise ValueError("service names cannot use reserved action alias prefixes")
            self.services[service.name] = service
            if service.container_name:
                self.services["container." + service.name] = service
            if service.process_pid:
                self.services["process." + service.name] = service
        all_names = list(self.services) + list(self.files.files) + list(self.docker_images)
        if len(set(all_names)) != len(all_names):
            raise ValueError("inventory aliases must be globally unique")

    def healthy(self, service: Service) -> bool:
        """A service with no configured health probe cannot be declared healthy."""
        events = Health(service).collect()
        return bool(events) and all(e.attributes.get("healthy") is True for e in events)

    def snapshot(self, target: str) -> Snapshot:
        """Re-read live identities and refuse unavailable or unknown targets."""
        if target in self.files.files:
            return self.files.inspect(target)
        if target in self.docker_images:
            image_id = self.docker_images[target]
            image = self.docker.image(image_id)
            if image.id != image_id or not self.docker.dangling(image_id):
                raise ValueError("image is not an exact unused dangling target")
            return Snapshot(
                target, "docker_image", image.id, revision({"image": image.id}), "dangling", False
            )
        if target not in self.services:
            raise LookupError("unknown inventory target")
        service = self.services[target]
        if target.startswith("container."):
            assert service.container_name is not None
            container = self.docker.container(service.container_name)
            state = container.attrs["State"]
            status = state.get("Status", "unknown")
            crashed = status in {"exited", "dead"} and (
                state.get("ExitCode", 0) != 0 or state.get("OOMKilled", False)
            )
            data = {
                "id": container.id,
                "image": container.attrs.get("Image"),
                "status": status,
                "started": state.get("StartedAt"),
                "finished": state.get("FinishedAt"),
                "restarts": container.attrs.get("RestartCount"),
                "exit": state.get("ExitCode"),
            }
            container_health = state.get("Health", {}).get("Status")
            healthy = status == "running" and container_health == "healthy"
            if status == "running" and container_health is None:
                healthy = self.healthy(service)
            data["healthy"] = healthy
            return Snapshot(
                target,
                "container",
                container.id,
                revision(data),
                "crashed" if crashed else status,
                healthy,
                service.critical,
            )
        if target.startswith("process."):
            assert service.process_pid is not None
            if service.process_pid in {1, os.getpid()}:
                raise ValueError("protected process target")
            process = psutil.Process(service.process_pid)
            identity = f"{process.pid}:{process.create_time()}"
            status = process.status()
            return Snapshot(
                target,
                "process",
                identity,
                revision({"identity": identity, "state": status}),
                status,
                process.is_running(),
                service.critical,
            )
        identity = "service:" + service.name
        service_data: dict[str, object] = {"inventory": service.model_dump()}
        paths = PathAccess(service.configs)
        for raw in service.configs:
            path = paths.authorize(raw)
            stat = path.stat()
            service_data["config:" + raw] = [
                stat.st_dev,
                stat.st_ino,
                stat.st_size,
                stat.st_mtime_ns,
            ]
        status = "unknown"
        if service.journal_unit:
            systemctl = shutil.which("systemctl")
            if not systemctl:
                raise RuntimeError("systemctl unavailable")
            service_data["unit"] = command(
                [
                    systemctl,
                    "show",
                    "--property=ActiveState,SubState,ExecMainStartTimestampMonotonic,FragmentPath",
                    "--",
                    service.journal_unit,
                ]
            )
            status = "active" if "ActiveState=active" in str(service_data["unit"]) else "inactive"
        healthy = self.healthy(service)
        service_data["healthy"] = healthy
        return Snapshot(
            target,
            "service",
            identity,
            revision(service_data),
            status,
            healthy,
            service.critical,
        )
