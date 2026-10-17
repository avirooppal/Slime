"""Concrete adapters with mocked Docker/systemd and isolated temporary POSIX files."""

import os
import threading
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from selfheal.config import Config, ManagedFileSettings, Service
from selfheal.remediation.contracts import TargetParams
from selfheal.remediation.docker_adapter import DockerAdapter
from selfheal.remediation.files import FileOperations, ManagedFile
from selfheal.remediation.native_backend import NativeBackend
from selfheal.safety.native_inventory import NativeInventory


def test_mock_docker_restart_and_health() -> None:
    """A crashed container uses immutable ID checks and explicit application health."""
    container = Mock(
        id="container-id",
        attrs={
            "State": {"Status": "exited", "ExitCode": 1},
            "Image": "image-id",
            "RestartCount": 1,
        },
    )
    docker = Mock()
    docker.container.return_value = container
    inventory = NativeInventory(
        Config(
            services=[
                Service(name="worker", container_name="worker", http_url="http://localhost/health")
            ]
        ),
        docker=docker,
    )
    snapshot = inventory.snapshot("container.worker")
    assert snapshot.state == "crashed" and not snapshot.healthy
    backend = NativeBackend(inventory)
    backend.execute("restart_container", snapshot, TargetParams(target="container.worker"))
    container.restart.assert_called_once_with(timeout=2)
    container.attrs["State"] = {"Status": "running", "ExitCode": 0, "Health": {"Status": "healthy"}}
    assert backend.verify("restart_container", snapshot, TargetParams(target="container.worker"))


def test_successful_exit_not_treated_as_crash() -> None:
    """A stopped job or deliberate clean exit cannot be auto-restarted as a crash."""
    docker = Mock()
    docker.container.return_value = Mock(
        id="id", attrs={"State": {"Status": "exited", "ExitCode": 0}}
    )
    inventory = NativeInventory(
        Config(services=[Service(name="worker", container_name="worker")]), docker=docker
    )
    assert inventory.snapshot("container.worker").state == "exited"


def test_docker_missing_warns_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing optional Docker degrades gracefully without installing the SDK."""
    monkeypatch.setattr(
        "selfheal.remediation.docker_adapter.importlib.import_module", Mock(side_effect=ImportError)
    )
    adapter = DockerAdapter()
    with pytest.warns(UserWarning, match="docker unavailable"), pytest.raises(RuntimeError):
        adapter.client()
    with pytest.raises(RuntimeError):
        adapter.client()


def test_free_docker_space_removed_from_native_backend() -> None:
    """free_docker_space is removed from the registry and rejected by NativeBackend."""
    image_id = "sha256:" + "a" * 64
    docker = Mock()
    docker.image.return_value = Mock(id=image_id)
    docker.dangling.return_value = True
    inventory = NativeInventory(Config(docker_images={"dangling.example": image_id}), docker=docker)
    snapshot = inventory.snapshot("dangling.example")
    backend = NativeBackend(inventory)
    assert not backend.available("free_docker_space", snapshot, TargetParams(target="dangling.example"))
    with pytest.raises(RuntimeError, match="native preconditions no longer hold"):
        backend.execute("free_docker_space", snapshot, TargetParams(target="dangling.example"))
    docker.client.assert_not_called()


def test_service_commands_are_argument_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """Service operations use a configured unit and never invoke a model-generated shell."""
    inventory = NativeInventory(
        Config(services=[Service(name="nginx", journal_unit="nginx.service")])
    )
    monkeypatch.setattr(inventory, "healthy", lambda service: True)
    monkeypatch.setattr(
        "selfheal.safety.native_inventory.shutil.which", lambda name: "/bin/systemctl"
    )
    monkeypatch.setattr(
        "selfheal.safety.native_inventory.command", lambda args: "ActiveState=active\n"
    )
    execute = Mock(return_value="")
    monkeypatch.setattr("selfheal.remediation.native_backend.command", execute)
    snapshot = inventory.snapshot("nginx")
    backend = NativeBackend(inventory)
    assert backend.available("reload_nginx", snapshot, TargetParams(target="nginx"))
    backend.execute("reload_nginx", snapshot, TargetParams(target="nginx"))
    assert execute.call_args.args[0] == [
        "/bin/systemctl",
        "--no-ask-password",
        "reload",
        "--",
        "nginx.service",
    ]
    assert not backend.rollback("reload_nginx", snapshot, Mock())


def test_process_pid_reuse_and_protected_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    """PID creation time is part of identity; PID 1 and Slime are never kill targets."""
    process = Mock(
        pid=1234, create_time=lambda: 10, status=lambda: "running", is_running=lambda: True
    )
    monkeypatch.setattr("selfheal.safety.native_inventory.psutil.Process", lambda pid: process)
    inventory = NativeInventory(Config(services=[Service(name="worker", process_pid=1234)]))
    snapshot = inventory.snapshot("process.worker")
    process.create_time = lambda: 20
    with pytest.raises(RuntimeError, match="changed"):
        NativeBackend(inventory).execute(
            "kill_runaway_process", snapshot, TargetParams(target="process.worker")
        )
    process.terminate.assert_not_called()
    inventory = NativeInventory(Config(services=[Service(name="worker", process_pid=1)]))
    with pytest.raises(ValueError, match="protected"):
        inventory.snapshot("process.worker")


def test_image_rollback_requires_specialized_adapter() -> None:
    """Generic native code refuses to invent container mounts/network/secrets on rollback."""
    inventory = NativeInventory(Config())
    backend = NativeBackend(inventory)
    assert not backend.available(
        "rollback_to_previous_image", Mock(), TargetParams(target="container.worker")
    )


@pytest.mark.skipif(os.name != "posix", reason="native file mutation requires POSIX directory APIs")
@pytest.mark.parametrize(
    "name,kind", [("clear_tmp_files", "tmp_file"), ("rotate_logs", "log_file")]
)
def test_private_file_operations_and_rollback(tmp_path: Path, name: str, kind: str) -> None:
    """Original contents survive execution and rollback in a private dedicated directory."""
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "old.log"
    path.write_text("original contents")
    path.chmod(0o600)
    os.utime(path, (time.time() - 3600, time.time() - 3600))
    file = ManagedFile("files.example", str(path), kind, 60, quiescent=True, contains_secrets=False)
    operations = FileOperations([file])
    snapshot = operations.inspect(file.target)
    receipt = operations.execute(name, snapshot)
    assert operations.verify(file.target)
    assert (private / receipt.rollback_data["backup"]).read_text() == "original contents"
    assert operations.rollback(snapshot, receipt)
    assert path.read_text() == "original contents"


@pytest.mark.skipif(os.name != "posix", reason="native file mutation requires POSIX directory APIs")
def test_file_rollback_never_clobbers_changed_log(tmp_path: Path) -> None:
    """A changed post-rotation file blocks rollback instead of discarding new logs."""
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "old.log"
    path.write_text("old logs")
    path.chmod(0o600)
    os.utime(path, (time.time() - 3600, time.time() - 3600))
    operations = FileOperations(
        [ManagedFile("files.example", str(path), "log_file", 60, True, False)]
    )
    snapshot = operations.inspect("files.example")
    receipt = operations.execute("rotate_logs", snapshot)
    path.write_text("new logs")
    assert not operations.rollback(snapshot, receipt)
    assert path.read_text() == "new logs"


def test_managed_files_disabled_without_attestation(tmp_path: Path) -> None:
    """An allowlisted pathname alone never grants file mutation permission."""
    path = tmp_path / "log"
    path.write_text("data")
    settings = ManagedFileSettings(
        target="files.example", path=str(path), kind="log_file", minimum_age_seconds=60
    )
    inventory = NativeInventory(Config(managed_files=[settings]))
    with pytest.raises(ValueError, match="attestations"):
        inventory.snapshot("files.example")


def test_action_alias_shadowing_rejected() -> None:
    """A second service name cannot shadow a critical generated container alias."""
    config = Config(
        services=[
            Service(name="worker", container_name="worker", critical=True),
            Service(name="container.worker", container_name="other"),
        ]
    )
    with pytest.raises(ValueError, match="reserved"):
        NativeInventory(config)


def test_service_config_change_updates_revision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Configuration metadata and health changes invalidate an earlier diagnosis."""
    path = tmp_path / "config"
    path.write_text("port=80")
    inventory = NativeInventory(Config(services=[Service(name="web", configs=[str(path)])]))
    monkeypatch.setattr(inventory, "healthy", lambda service: False)
    before = inventory.snapshot("web")
    path.write_text("port=8080")
    after = inventory.snapshot("web")
    assert before.revision != after.revision
    monkeypatch.setattr(inventory, "healthy", lambda service: True)
    assert inventory.snapshot("web").revision != after.revision


def test_native_stop_set_during_last_container_read() -> None:
    """A late kill request still prevents the native Docker restart RPC."""
    stop = threading.Event()
    container = Mock(id="id", attrs={"State": {"Status": "exited", "ExitCode": 1}})
    docker = Mock()
    count = 0

    def get_container(name: str) -> Mock:
        """Set stop after the final inventory and availability reads."""
        nonlocal count
        count += 1
        if count == 4:
            stop.set()
        return container

    docker.container.side_effect = get_container
    inventory = NativeInventory(
        Config(
            services=[
                Service(name="worker", container_name="worker", http_url="http://localhost/health")
            ]
        ),
        docker=docker,
    )
    snapshot = inventory.snapshot("container.worker")
    with pytest.raises(InterruptedError):
        NativeBackend(inventory).execute(
            "restart_container", snapshot, TargetParams(target="container.worker"), stop.is_set
        )
    container.restart.assert_not_called()


def test_real_optional_sdk_does_not_load_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use actual SDK constructors while mocking every network call and credential lookup."""
    docker = pytest.importorskip("docker", reason="optional Docker SDK compatibility check")
    credential_lookup = Mock(side_effect=AssertionError("credential file lookup forbidden"))
    monkeypatch.setattr("docker.auth.config.find_config_file", credential_lookup)

    def version(client: object, api_version: bool = True) -> dict[str, str]:
        """Negotiation happens only after ambient authentication is disabled."""
        assert client.trust_env is False
        return {"ApiVersion": "1.45"}

    monkeypatch.setattr(docker.APIClient, "version", version)
    monkeypatch.setattr(docker.APIClient, "ping", lambda client: True)
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    adapter = DockerAdapter()
    client = adapter.client()
    try:
        assert client.api.trust_env is False
        assert client.api._general_configs == {"auths": {}}
        assert all(not value for value in client.api._auth_configs.auths.values())
        assert client.api.base_url in {"http+docker://localhost", "http+docker://localnpipe"}
        credential_lookup.assert_not_called()
    finally:
        client.close()
