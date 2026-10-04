"""Sampled stability verification with injectable clocks and immediate stop checks."""

import math
import time
from collections.abc import Callable
from dataclasses import dataclass

from selfheal.diagnosis.limits import BoundedRead


@dataclass(frozen=True)
class Verification:
    """Only stable=True qualifies an execution as successful."""

    stable: bool
    reason: str
    samples: int
    elapsed_seconds: float
    flapping: bool = False


class StabilityVerifier:
    """Require healthy observations spanning the full configured stability window."""

    def __init__(
        self,
        window_seconds: float = 120,
        interval_seconds: float = 5,
        timeout_seconds: float = 300,
        probe_timeout_seconds: float = 3,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], object] = time.sleep,
    ) -> None:
        """Inject clock/wait for fast deterministic tests without skipping stability."""
        if (
            any(
                not math.isfinite(v) or v <= 0
                for v in (window_seconds, interval_seconds, timeout_seconds, probe_timeout_seconds)
            )
            or timeout_seconds < window_seconds
        ):
            raise ValueError("positive window/interval and sufficient timeout required")
        self.window, self.interval, self.timeout = window_seconds, interval_seconds, timeout_seconds
        self.clock, self.wait = clock, wait
        self.probe_timeout = probe_timeout_seconds
        self.reader = BoundedRead()

    def verify(self, probe: Callable[[], bool], stopped: Callable[[], bool]) -> Verification:
        """Fail on the first unhealthy observation; do not loop through flaps."""
        start = self.clock()
        healthy_since: float | None = None
        samples = 0
        while True:
            elapsed = self.clock() - start
            if stopped():
                return Verification(False, "kill_switch", samples, elapsed)
            if elapsed > self.timeout:
                return Verification(False, "verification_timeout", samples, elapsed)
            try:
                healthy = (
                    self.reader.call(
                        probe, min(self.probe_timeout, max(0.001, self.timeout - elapsed)), stopped
                    )
                    is True
                )
            except TimeoutError:
                return Verification(False, "probe_timeout", samples, self.clock() - start)
            except InterruptedError:
                return Verification(False, "kill_switch", samples, self.clock() - start)
            except Exception:  # noqa: BLE001 - unknown probe failures are never healthy
                return Verification(False, "probe_failed", samples, self.clock() - start)
            samples += 1
            elapsed = self.clock() - start
            if stopped():
                return Verification(False, "kill_switch", samples, elapsed)
            if elapsed > self.timeout:
                return Verification(False, "verification_timeout", samples, elapsed)
            if not healthy:
                return Verification(False, "unhealthy", samples, elapsed, healthy_since is not None)
            if healthy_since is None:
                healthy_since = self.clock()
            if self.clock() - healthy_since >= self.window:
                return Verification(True, "stability_passed", samples, elapsed)
            self.wait(
                min(
                    self.interval,
                    self.window - (self.clock() - healthy_since),
                    max(0.001, self.timeout - elapsed),
                )
            )
