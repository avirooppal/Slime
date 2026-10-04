"""Single-worker bounds for read-only operations; never used to run mutations."""

import queue
import threading
import time
from collections.abc import Callable
from typing import TypeVar, cast

T = TypeVar("T")


class BoundedRead:
    """A deadline cannot spawn unlimited replacement workers for a stuck read."""

    def __init__(self) -> None:
        """Create one worker admission lock per long-lived runner."""
        self.busy = threading.Lock()

    def call(
        self, operation: Callable[[], T], timeout: float, stopped: Callable[[], bool] | None = None
    ) -> T:
        """Bound caller latency; late read-only results are discarded after timeout."""
        if not self.busy.acquire(blocking=False):
            raise TimeoutError("earlier read-only probe is still running")
        output: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

        def worker() -> None:
            """Retain at most one result and release admission after IO finishes."""
            try:
                result: tuple[bool, object] = (True, operation())
            except Exception as error:  # noqa: BLE001 - relay adapter errors to the caller thread
                result = (False, error)
            finally:
                self.busy.release()
            output.put(result)

        threading.Thread(target=worker, daemon=True).start()
        deadline = time.monotonic() + timeout
        while True:
            if stopped is not None and stopped():
                raise InterruptedError("read-only caller stopped")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read-only deadline exhausted")
            try:
                ok, result = output.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                continue
            if ok:
                return cast(T, result)
            if isinstance(result, Exception):
                raise result
            raise RuntimeError("invalid read-only worker result")
