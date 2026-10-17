"""Prepare a private playground; never launch the service or replace existing state."""
import socket
import sys
from pathlib import Path

import yaml

from selfheal.config import Config, ManagedProcessSettings, Service

root = Path(__file__).resolve().parent
destination = root / ".slime/config.yaml"
if destination.exists():
    print("Playground already prepared. Existing configuration preserved.")
else:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = Config(
        database=str(root / ".slime/slime.db"), metrics_enabled=False,
        poll_seconds=2, stability_seconds=5,
        services=[Service(
            name="playground", http_url=f"http://127.0.0.1:{port}/health",
            managed_process=ManagedProcessSettings(
                executable=str(Path(sys.executable).resolve()),
                args=[str(root / "app.py"), str(port)], cwd=str(root),
                startup_grace_seconds=5,
            ),
        )],
    )
    config.safety.verification_interval_seconds = 1
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        yaml.safe_dump(config.model_dump(mode="json"), stream, sort_keys=False)
    print("Prepared. The app is intentionally stopped; Slime can detect and start it.")
print("Config: " + str(destination))
print("Run selfheal run --config .slime/config.yaml --once from: " + str(root))
