"""Collector isolation, path identity and bounded subprocess helpers."""

import subprocess
import threading
import warnings
from pathlib import Path


class Warnings:
    """Emit one clear warning per failing component per process."""

    def __init__(self) -> None:
        """Start an empty component warning set."""
        self.seen: set[str] = set()

    def warn(self, component: str, reason: str) -> None:
        """Warn once without logging attacker-controlled exception messages."""
        if component not in self.seen:
            warnings.warn(
                f"{component} unavailable: {reason}; remaining collectors continue", stacklevel=2
            )
            self.seen.add(component)


def pinned_path(path: str) -> Path:
    """Resolve an explicitly authorized path at configuration load time."""
    return Path(path).absolute().resolve(strict=False)


def check_path(original: str, pinned: Path) -> Path:
    """Reject a configured pathname redirected through a new symlink."""
    if Path(original).absolute().resolve(strict=True) != pinned:
        raise ValueError("configured path changed identity")
    return pinned


def command(args: list[str], timeout: float = 3, limit: int = 65536) -> str:
    """Run a read-only argument list with time and returned-output bounds."""
    output = bytearray()
    capped = threading.Event()
    with subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False
    ) as process:
        assert process.stdout is not None
        stream = process.stdout

        def read_output() -> None:
            """Drain only the permitted byte budget, then stop the owned child."""
            while len(output) <= limit:
                chunk = stream.read(min(4096, limit + 1 - len(output)))
                if not chunk:
                    return
                output.extend(chunk)
                if len(output) > limit:
                    capped.set()
                    process.kill()
                    return

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)
            reader.join(timeout=1)
            raise
        reader.join(timeout=1)
        if code and not capped.is_set():
            raise subprocess.CalledProcessError(code, args)
    return bytes(output[:limit]).decode("utf-8", errors="replace")
