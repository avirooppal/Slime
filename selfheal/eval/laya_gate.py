"""Compare optional Laya with local retrieval and runbooks on held-out JSONL."""

import hashlib
import importlib.util
import json
import statistics
import time
from pathlib import Path

from selfheal.config import Config
from selfheal.diagnosis.laya_classifier import INCIDENT_TYPES, LayaClassifier
from selfheal.diagnosis.laya_contracts import LayaEvaluationReport
from selfheal.diagnosis.retrieval import MemoryRetriever
from selfheal.diagnosis.runbooks import RunbookEngine
from selfheal.models import Event, Incident
from selfheal.storage.store import Store


def _label(action: str | None) -> str:
    """Map a local proposed repair to the comparable closed-set class."""
    return {"restart_container": "container_crash", "restart_service": "service_health_hang",
            "kill_runaway_process": "process_crash"}.get(action or "", "healthy_or_unknown")


def _ece(values: list[tuple[float, bool]]) -> float:
    """Calculate five-bin expected calibration error."""
    error = 0.0
    for bucket in range(5):
        selected = [(p, ok) for p, ok in values if min(int(p * 5), 4) == bucket]
        if selected:
            error += len(selected) / len(values) * abs(
                statistics.mean(p for p, _ in selected)
                - statistics.mean(int(ok) for _, ok in selected))
    return error


def evaluate_laya(
    dataset: Path, config: Config, store: Store, router: object | None = None
) -> LayaEvaluationReport:
    """Score unique labeled cases; synthetic chaos labels alone cannot pass this gate."""
    raw = dataset.read_bytes()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if router is None and importlib.util.find_spec("laya") is None:
        raise ImportError("install the optional laya extra before running evaluation")
    if any("fault_type" in row for row in rows):
        raise ValueError("synthetic chaos labels cannot serve as the held-out activation gate")
    ids = [str(row.get("scenario_name", "")) for row in rows]
    if (len(rows) < 20 or len(set(ids)) != len(ids) or any(not name for name in ids)
        or not any(row.get("expected_type") == "healthy_or_unknown" for row in rows)):
        raise ValueError("need 20 unique held-out cases including healthy/negated examples")
    classifier = LayaClassifier(config, store, router=router)
    memory, runbooks = MemoryRetriever(store), RunbookEngine(config)
    laya_results: list[tuple[float, bool]] = []
    base_results: list[tuple[float, bool]] = []
    laya_times: list[float] = []
    base_times: list[float] = []
    for row in rows:
        expected = str(row["expected_type"])
        if expected not in INCIDENT_TYPES:
            raise ValueError("unknown expected incident class")
        incident = Incident.model_validate(row["incident"])
        events = [Event.model_validate(item) for item in row["events"]]
        started = time.perf_counter()
        baseline = memory.diagnose(incident, events)
        if baseline.selected is None:
            baseline = runbooks.diagnose(incident, events)
        base_times.append((time.perf_counter() - started) * 1000)
        candidate = baseline.selected
        base_results.append((candidate.confidence if candidate else 0.0,
                             _label(candidate.proposed_action if candidate else None) == expected))
        started = time.perf_counter()
        try:
            prediction = classifier.predict(incident, events)
            laya_results.append((prediction.calibrated_confidence,
                                 prediction.predicted_class == expected))
        except (ValueError, KeyError, TypeError, ImportError):
            laya_results.append((0.0, False))
        laya_times.append((time.perf_counter() - started) * 1000)
    return LayaEvaluationReport(
        model="english", dataset_sha256=hashlib.sha256(raw).hexdigest(),
        held_out_count=len(rows),
        accuracy=statistics.mean(int(ok) for _, ok in laya_results),
        baseline_accuracy=statistics.mean(int(ok) for _, ok in base_results),
        ece=_ece(laya_results), baseline_ece=_ece(base_results),
        median_latency_ms=statistics.median(laya_times),
        baseline_median_latency_ms=statistics.median(base_times),
    )
