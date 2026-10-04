"""Robust rolling statistics without NumPy or a heavyweight backend."""

import math
from collections import defaultdict, deque
from statistics import median


class Anomalies:
    """Detect robust z-score anomalies and median shifts after warmup."""

    def __init__(self, window: int = 60, warmup: int = 12, z_limit: float = 6) -> None:
        """Set a bounded rolling window and conservative warmup."""
        if warmup < 8 or window < warmup:
            raise ValueError("window must contain warmup of at least eight samples")
        self.samples: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self.warmup, self.z_limit = warmup, z_limit

    def sample(self, key: str, value: float, hard_limit: float | None = None) -> str | None:
        """Compare against previous samples, then append this finite sample."""
        if not math.isfinite(value):
            raise ValueError("metric must be finite")
        history = self.samples[key]
        reason = None
        if hard_limit is not None and value > hard_limit:
            reason = "hard_limit"
        elif len(history) >= self.warmup:
            center = median(history)
            scale = max(1.4826 * median(abs(x - center) for x in history), 1.0)
            if abs(value - center) / scale > self.z_limit:
                reason = "robust_z_score"
            if reason is None:
                values = list(history) + [value]
                baseline, recent = values[:-4], values[-4:]
                baseline_center = median(baseline)
                baseline_scale = max(
                    1.4826 * median(abs(x - baseline_center) for x in baseline), 1.0
                )
                if abs(median(recent) - baseline_center) > self.z_limit * baseline_scale / 2:
                    reason = "median_change_point"
        history.append(value)
        return reason
