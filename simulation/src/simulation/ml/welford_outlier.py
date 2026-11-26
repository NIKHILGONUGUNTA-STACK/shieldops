"""Streaming real-time metric outlier detection using Welford's continuous variance algorithm."""

import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from simulation.ml.markov_sequencer import MarkovSequencer
from simulation.ml.models import (
    OutlierBaselineProfile,
    OutlierEvaluationResult,
    OutlierMetricSummary,
)


class WelfordMetricTracker:
    """Computes online mean, variance, and standard deviation in a single pass with O(1) space and time."""

    def __init__(
        self,
        count: int = 0,
        mean: float = 0.0,
        m2: float = 0.0,
        min_val: float = float("inf"),
        max_val: float = float("-inf"),
    ):
        self.count = count
        self.mean = mean
        self.m2 = m2
        self.min_val = min_val if count > 0 else float("inf")
        self.max_val = max_val if count > 0 else float("-inf")

    def update(self, val: float) -> None:
        """Applies Welford's one-pass update step."""
        self.count += 1
        delta = val - self.mean
        self.mean += delta / self.count
        delta2 = val - self.mean
        self.m2 += delta * delta2
        self.min_val = min(self.min_val, val)
        self.max_val = max(self.max_val, val)

    @property
    def variance(self) -> float:
        return self.m2 / (self.count - 1) if self.count >= 2 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(max(0.0, self.variance))

    def z_score(self, val: float) -> float:
        """Calculates standard deviation units from the running mean."""
        sigma = self.std_dev
        if self.count < 3 or sigma < 1e-4:
            return 0.0
        return (val - self.mean) / sigma

    def to_summary(self, metric_name: str) -> OutlierMetricSummary:
        return OutlierMetricSummary(
            metric_name=metric_name,
            count=self.count,
            mean=round(self.mean, 2),
            variance=round(self.variance, 2),
            std_dev=round(self.std_dev, 2),
            min_val=round(self.min_val, 2) if self.count > 0 else 0.0,
            max_val=round(self.max_val, 2) if self.count > 0 else 0.0,
        )


class StreamingOutlierDetector:
    """Per-endpoint multi-metric streaming outlier detector for payload volumes and response latencies."""

    def __init__(self, z_threshold: float = 3.5):
        self.z_threshold = z_threshold
        # trackers[canonical_endpoint][metric_name] -> WelfordMetricTracker
        self.trackers: Dict[str, Dict[str, WelfordMetricTracker]] = {}

    def get_or_create_tracker(self, endpoint: str, metric: str) -> WelfordMetricTracker:
        if endpoint not in self.trackers:
            self.trackers[endpoint] = {}
        if metric not in self.trackers[endpoint]:
            self.trackers[endpoint][metric] = WelfordMetricTracker()
        return self.trackers[endpoint][metric]

    def update(
        self,
        method: str,
        path: str,
        payload_bytes: int,
        latency_ms: float,
    ) -> None:
        """Ingests a completed transaction and updates running endpoint statistics."""
        endpoint = MarkovSequencer.normalize_endpoint(method, path)
        self.get_or_create_tracker(endpoint, "payload_bytes").update(float(payload_bytes))
        self.get_or_create_tracker(endpoint, "latency_ms").update(float(latency_ms))

    def evaluate(
        self,
        method: str,
        path: str,
        payload_bytes: int,
        latency_ms: float,
        record_observation: bool = False,
    ) -> OutlierEvaluationResult:
        """Evaluates whether an observed transaction is a statistical outlier."""
        endpoint = MarkovSequencer.normalize_endpoint(method, path)
        payload_tracker = self.get_or_create_tracker(endpoint, "payload_bytes")
        latency_tracker = self.get_or_create_tracker(endpoint, "latency_ms")

        payload_z = payload_tracker.z_score(float(payload_bytes))
        latency_z = latency_tracker.z_score(float(latency_ms))

        # We care primarily about positive spikes (excessive payload size or latency degradation)
        effective_payload_z = max(0.0, payload_z)
        effective_latency_z = max(0.0, latency_z)
        max_z = max(effective_payload_z, effective_latency_z)

        # Normalize score into [0.0, 1.0] sigmoid centered at (z_threshold - 0.5)
        # E.g. at z=3.5, score ~ 0.73; at z=5.0, score ~ 0.95
        outlier_score = 1.0 / (1.0 + math.exp(-min(10.0, max(0.0, max_z - (self.z_threshold - 0.5)))))
        if max_z < 1.0:
            outlier_score = 0.0

        is_payload_outlier = effective_payload_z >= self.z_threshold and payload_tracker.count >= 5
        is_latency_outlier = effective_latency_z >= self.z_threshold and latency_tracker.count >= 5
        is_outlier = is_payload_outlier or is_latency_outlier

        outlier_type = None
        if is_payload_outlier and is_latency_outlier:
            outlier_type = "COMBO_VOLUMETRIC_AND_LATENCY"
        elif is_payload_outlier:
            outlier_type = "VOLUMETRIC_EXFILTRATION"
        elif is_latency_outlier:
            outlier_type = "LATENCY_DEGRADATION"

        details = {
            "payload_mean": round(payload_tracker.mean, 1),
            "payload_std": round(payload_tracker.std_dev, 1),
            "payload_count": payload_tracker.count,
            "latency_mean": round(latency_tracker.mean, 1),
            "latency_std": round(latency_tracker.std_dev, 1),
            "latency_count": latency_tracker.count,
        }

        if record_observation:
            payload_tracker.update(float(payload_bytes))
            latency_tracker.update(float(latency_ms))

        return OutlierEvaluationResult(
            endpoint=endpoint,
            payload_bytes=payload_bytes,
            latency_ms=latency_ms,
            payload_z_score=round(payload_z, 2),
            latency_z_score=round(latency_z, 2),
            max_z_score=round(max_z, 2),
            outlier_score=round(outlier_score, 3),
            is_outlier=is_outlier,
            outlier_type=outlier_type,
            details=details,
        )

    def train_baseline(
        self,
        records: List[Dict[str, Any]],
        name: str = "production_outlier_profile",
    ) -> OutlierBaselineProfile:
        """Fits streaming baseline distributions over a list of historical transaction records."""
        for rec in records:
            method = rec.get("method", "GET")
            path = rec.get("path", "/")
            bytes_val = int(rec.get("payload_bytes", rec.get("response_size", 0)))
            latency_val = float(rec.get("latency_ms", rec.get("duration_ms", 10.0)))
            self.update(method, path, bytes_val, latency_val)

        return self.export_profile(name=name)

    def export_profile(self, name: str = "production_outlier_profile") -> OutlierBaselineProfile:
        """Exports the current tracker states into a serializable profile."""
        endpoints_dict: Dict[str, Dict[str, OutlierMetricSummary]] = {}
        total_obs = 0

        for ep, metrics in self.trackers.items():
            endpoints_dict[ep] = {}
            for metric_name, tracker in metrics.items():
                endpoints_dict[ep][metric_name] = tracker.to_summary(metric_name)
                total_obs = max(total_obs, tracker.count)

        return OutlierBaselineProfile(
            name=name,
            version="1.0.0",
            total_observations=total_obs,
            z_threshold=self.z_threshold,
            endpoints=endpoints_dict,
        )

    def load_profile(self, profile: OutlierBaselineProfile) -> None:
        """Restores tracker states from a baseline profile."""
        self.z_threshold = profile.z_threshold
        self.trackers.clear()

        for ep, metrics in profile.endpoints.items():
            self.trackers[ep] = {}
            for metric_name, summary in metrics.items():
                m2 = summary.variance * (summary.count - 1) if summary.count >= 2 else 0.0
                self.trackers[ep][metric_name] = WelfordMetricTracker(
                    count=summary.count,
                    mean=summary.mean,
                    m2=m2,
                    min_val=summary.min_val,
                    max_val=summary.max_val,
                )

    def save_profile_file(self, path: Union[str, Path], name: str = "production_outlier_profile") -> None:
        profile = self.export_profile(name=name)
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(profile.model_dump(), indent=2), encoding="utf-8")

    def load_profile_file(self, path: Union[str, Path]) -> None:
        in_path = Path(path)
        if not in_path.exists():
            raise FileNotFoundError(f"Outlier baseline file not found at: {in_path}")
        data = json.loads(in_path.read_text(encoding="utf-8"))
        self.load_profile(OutlierBaselineProfile(**data))
