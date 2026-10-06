"""Turn explicit workflow targets into a reusable local agent configuration."""

import shutil
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from selfheal.config import Config, ManagedProcessSettings, Service, load_config


def prepare_agent(
    config: Path, name: str, health: str | None, logs: list[Path],
    executable: str | None, args: list[str], cwd: Path,
) -> Config:
    """Validate before writing; never replace an operator's existing configuration."""
    if config.exists():
        if health or logs or executable or args or name != "app" or cwd != Path("."):
            raise ValueError(
                "Configuration already exists. Run without target options to reuse it, "
                "or choose a new --config path."
            )
        return load_config(config)
    if not (health or logs or executable):
        raise ValueError(
            "Choose a target: --health http://localhost:8000/health, "
            "--log app.log, or --executable python --arg worker.py."
        )
    if args and not executable:
        raise ValueError("--arg requires --executable")
    if health:
        url = urlsplit(health)
        if (url.scheme not in {"http", "https"} or not url.hostname
                or url.username is not None or url.password is not None
                or url.query or url.fragment):
            raise ValueError("--health must be an HTTP(S) URL without credentials, query or fragment")
        _ = url.port  # Reject malformed ports before writing or starting collectors.
    directory = cwd.resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("--cwd must be a directory")
    log_paths = [p if p.is_absolute() else directory / p for p in logs]
    for path in log_paths:
        if path.exists() and not path.is_file():
            raise ValueError("--log must name a file")
    managed = None
    if executable:
        candidate = directory / executable
        resolved = str(candidate) if candidate.is_file() else shutil.which(executable)
        if not resolved:
            raise ValueError("Executable not found; provide a path or a command available on PATH")
        managed = ManagedProcessSettings(
            executable=str(Path(resolved).absolute()), args=args, cwd=str(directory),
        )
    destination = config.absolute()
    settings = Config(
        database=str(destination.parent / "slime.db"),
        disk_paths=[directory.anchor],
        services=[Service(name=name, http_url=health,
                          logs=[str(p.absolute()) for p in log_paths], managed_process=managed)],
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        yaml.safe_dump(settings.model_dump(mode="json"), stream, sort_keys=False)
    return settings
