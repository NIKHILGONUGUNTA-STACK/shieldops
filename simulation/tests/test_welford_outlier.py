"""Tests for streaming Welford metric tracker and outlier detector."""

import math
from pathlib import Path
import pytest

from simulation.ml.welford_outlier import (
    StreamingOutlierDetector,
    WelfordMetricTracker,
)


def test_welford_tracker_basic_stats():
    tracker = WelfordMetricTracker()
    values = [10.0, 20.0, 30.0, 40.0, 50.0]
    for v in values:
        tracker.update(v)

    assert tracker.count == 5
    assert tracker.mean == 30.0
    # Sample variance of [10, 20, 30, 40, 50] is 250.0
    assert math.isclose(tracker.variance, 250.0, rel_tol=1e-5)
    # Sample std dev is sqrt(250) ~ 15.811388
    assert math.isclose(tracker.std_dev, 15.811388, rel_tol=1e-5)
    assert tracker.min_val == 10.0
    assert tracker.max_val == 50.0

    # Z-scores
    assert math.isclose(tracker.z_score(30.0), 0.0, abs_tol=1e-5)
    z_high = tracker.z_score(30.0 + (3.5 * tracker.std_dev))
    assert math.isclose(z_high, 3.5, rel_tol=1e-4)


@pytest.fixture
def trained_detector():
    """Builds a detector with established normal baseline for customer endpoint."""
    detector = StreamingOutlierDetector(z_threshold=3.5)
    # Ingest 40 normal responses: bytes around 1000 +- 50, latency around 30 +- 5
    import random
    rng = random.Random(42)
    for _ in range(40):
        size = int(rng.gauss(1000, 50))
        lat = rng.gauss(30, 5)
        detector.update("GET", "/api/v1/customers/cust-123", size, lat)
    return detector


def test_detector_normal_transaction(trained_detector):
    result = trained_detector.evaluate("GET", "/api/v1/customers/cust-999", payload_bytes=1020, latency_ms=32.0)
    assert result.is_outlier is False
    assert result.max_z_score < 1.5
    assert result.outlier_type is None


def test_detector_volumetric_exfiltration(trained_detector):
    # Baseline payload is ~1000 with std ~50.
    # A payload of 10,000 bytes is > 100 sigma above mean!
    result = trained_detector.evaluate("GET", "/api/v1/customers/cust-999", payload_bytes=10000, latency_ms=32.0)
    assert result.is_outlier is True
    assert result.outlier_type == "VOLUMETRIC_EXFILTRATION"
    assert result.payload_z_score > 3.5
    assert result.outlier_score > 0.8


def test_detector_latency_degradation(trained_detector):
    # Baseline latency is ~30ms with std ~5.
    # Latency of 500ms is > 90 sigma!
    result = trained_detector.evaluate("GET", "/api/v1/customers/cust-999", payload_bytes=1000, latency_ms=500.0)
    assert result.is_outlier is True
    assert result.outlier_type == "LATENCY_DEGRADATION"
    assert result.latency_z_score > 3.5


def test_detector_combo_outlier(trained_detector):
    result = trained_detector.evaluate("GET", "/api/v1/customers/cust-999", payload_bytes=12000, latency_ms=600.0)
    assert result.is_outlier is True
    assert result.outlier_type == "COMBO_VOLUMETRIC_AND_LATENCY"


def test_detector_export_and_reload(tmp_path, trained_detector):
    file_path = tmp_path / "outlier_profile.json"
    trained_detector.save_profile_file(file_path, name="test_export")
    assert file_path.exists()

    new_detector = StreamingOutlierDetector()
    new_detector.load_profile_file(file_path)

    # Verify same behavior
    res_orig = trained_detector.evaluate("GET", "/api/v1/customers/cust-999", 10000, 32.0)
    res_loaded = new_detector.evaluate("GET", "/api/v1/customers/cust-999", 10000, 32.0)

    assert res_orig.is_outlier == res_loaded.is_outlier
    assert math.isclose(res_orig.payload_z_score, res_loaded.payload_z_score, rel_tol=1e-4)
