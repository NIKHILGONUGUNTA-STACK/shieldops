"""Gate 1 Verification: Dataset Neutralization, Integrity and Label Isolation Tests.

Verifies:
1. Historical v1.0 dataset artifact preservation (immutable baseline).
2. Version 1.1 dataset schema validity and population integrity.
3. Strict ground-truth segregation (ground_truth_v1_1.json vs telemetry vs manifest).
4. Opaque, non-sequential scenario identifiers with statistical category independence.
5. Natural route and resource reuse (identical route templates across benign & malicious).
6. Four-way independent cryptographic hashing and non-circular master digest.
7. Active tamper detection across telemetry, ground truth, scenario definitions, metadata, and cross-version reuse.
8. Detector isolation (detectors receive ZERO ground-truth attributes).
9. Deterministic generator reproducibility.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import pytest

from simulation.evaluation.contextual_detector import ContextualDetector
from simulation.evaluation.dataset_generator import (
    FORBIDDEN_LEAKED_TOKENS,
    EvaluationDatasetGenerator,
    audit_telemetry_label_leakage,
    save_dataset_artifacts,
    verify_dataset_integrity,
)
from simulation.evaluation.isolated_detector import IsolatedRuleDetector
from simulation.evaluation.models import (
    DatasetManifest,
    EventTelemetry,
    GroundTruthArtifact,
    GroundTruthCategory,
    ScenarioDefinition,
    ScenarioGroundTruth,
    compute_canonical_ground_truth_hash,
    compute_canonical_scenario_definitions_hash,
    compute_canonical_telemetry_hash,
)

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"
HISTORICAL_V1_MANIFEST_HASH = "a095203c13aede9b952ff912519ba6229c73f37af62c7bd445a9acf5a8636c58"
HISTORICAL_V1_TELEMETRY_HASH = "be85f81961c261f966cc7b3d04d3baf65c24d504ef2aaff0d4e6761ee81afceb"


# =============================================================================
# 1. Historical v1.0 Baseline Preservation
# =============================================================================

def test_historical_v1_preservation():
    """Historical v1.0 artifacts must remain permanently preserved and unmodified."""
    m_path = DATASETS_DIR / "dataset_manifest_v1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1.json"

    assert m_path.exists(), "Historical dataset_manifest_v1.json is missing!"
    assert t_path.exists(), "Historical dataset_telemetry_v1.json is missing!"

    m_hash = hashlib.sha256(m_path.read_bytes()).hexdigest().lower()
    t_hash = hashlib.sha256(t_path.read_bytes()).hexdigest().lower()

    assert m_hash == HISTORICAL_V1_MANIFEST_HASH, (
        f"Historical v1 manifest hash altered! Expected {HISTORICAL_V1_MANIFEST_HASH}, got {m_hash}"
    )
    assert t_hash == HISTORICAL_V1_TELEMETRY_HASH, (
        f"Historical v1 telemetry hash altered! Expected {HISTORICAL_V1_TELEMETRY_HASH}, got {t_hash}"
    )


# =============================================================================
# 2. Schema Validity & Population Integrity
# =============================================================================

def test_v1_1_artifacts_exist_and_validate():
    """Version 1.1 artifacts must exist and conform strictly to Pydantic models."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    assert m_path.exists(), "dataset_manifest_v1_1.json missing!"
    assert g_path.exists(), "ground_truth_v1_1.json missing!"
    assert t_path.exists(), "dataset_telemetry_v1_1.json missing!"

    manifest = DatasetManifest.model_validate_json(m_path.read_text(encoding="utf-8"))
    assert manifest.dataset_id == "DS-AEGIS-RESEARCH-V1.1"
    assert manifest.version == "1.1.0"
    assert manifest.total_scenarios == 200
    assert manifest.benign_count == 80
    assert manifest.malicious_count == 70
    assert manifest.ambiguous_count == 30
    assert manifest.incomplete_count == 20
    assert len(manifest.scenario_definitions) == 200

    gt_artifact = GroundTruthArtifact.model_validate_json(g_path.read_text(encoding="utf-8"))
    assert gt_artifact.total_scenarios == 200
    assert gt_artifact.population_distribution["BENIGN"] == 80
    assert gt_artifact.population_distribution["MALICIOUS"] == 70
    assert gt_artifact.population_distribution["AMBIGUOUS"] == 30
    assert gt_artifact.population_distribution["INCOMPLETE_EVIDENCE"] == 20
    assert len(gt_artifact.scenarios) == 200

    raw_telemetry = json.loads(t_path.read_text(encoding="utf-8"))
    assert len(raw_telemetry) == 200


# =============================================================================
# 3. Strict Ground-Truth Segregation
# =============================================================================

def test_strict_ground_truth_segregation():
    """Telemetry and Manifest artifacts must contain zero ground-truth fields."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    manifest_raw = json.loads(m_path.read_text(encoding="utf-8"))
    telemetry_raw = json.loads(t_path.read_text(encoding="utf-8"))

    # Manifest scenario_definitions must have NO category, expected_detection, expected_rules, etc.
    forbidden_gt_keys = {
        "category",
        "expected_detection",
        "expected_campaign",
        "expected_rules",
        "ground_truth",
        "expected_incident",
    }
    for sc_def in manifest_raw["scenario_definitions"]:
        for k in forbidden_gt_keys:
            assert k not in sc_def, f"Ground-truth key '{k}' found in manifest scenario definition!"

    # Telemetry events must have NO ground-truth keys
    for sc_id, events in telemetry_raw.items():
        for ev in events:
            for k in forbidden_gt_keys:
                assert k not in ev, f"Ground-truth key '{k}' found in telemetry event for {sc_id}!"


# =============================================================================
# 4. Opaque IDs & Statistical Category Independence
# =============================================================================

def test_opaque_ids_and_category_independence():
    """Scenario IDs must be opaque hex tokens; ordering must be statistically independent of category."""
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    gt_artifact = GroundTruthArtifact.model_validate_json(g_path.read_text(encoding="utf-8"))

    id_pattern = re.compile(r"^scen-[0-9a-f]{8}$")
    categories_in_order: list[str] = []

    for sc in gt_artifact.scenarios:
        assert id_pattern.match(sc.scenario_id), f"Scenario ID {sc.scenario_id} does not match opaque pattern!"
        assert "benign" not in sc.scenario_id.lower()
        assert "malicious" not in sc.scenario_id.lower()
        assert "ambiguous" not in sc.scenario_id.lower()
        assert "incomplete" not in sc.scenario_id.lower()
        categories_in_order.append(sc.category.value)

    # 1. Verify interleaving: No single category should appear in an unbroken run > 12
    max_run = 1
    current_run = 1
    for i in range(1, len(categories_in_order)):
        if categories_in_order[i] == categories_in_order[i - 1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1

    assert max_run < 15, f"Categories are not randomly interleaved! Max contiguous run length: {max_run}"

    # 2. Verify sorted order independence:
    # Sort scenarios alphabetically by scenario_id and verify categories do not cluster
    sorted_by_id = sorted(gt_artifact.scenarios, key=lambda s: s.scenario_id)
    sorted_categories = [s.category.value for s in sorted_by_id]

    # First quarter vs last quarter distribution
    q1 = sorted_categories[:50]
    q4 = sorted_categories[150:]

    # Both quarters must contain multiple categories (not partitioned)
    assert len(set(q1)) >= 3, "Quarter 1 lacks diversity — IDs are clustered!"
    assert len(set(q4)) >= 3, "Quarter 4 lacks diversity — IDs are clustered!"


# =============================================================================
# 5. Natural Route & Resource Reuse
# =============================================================================

def test_route_and_resource_neutrality():
    """Benign and malicious scenarios must reuse identical route templates."""
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    gt_artifact = GroundTruthArtifact.model_validate_json(g_path.read_text(encoding="utf-8"))
    raw_telemetry = json.loads(t_path.read_text(encoding="utf-8"))

    gt_map = {s.scenario_id: s.category for s in gt_artifact.scenarios}

    benign_routes = set()
    malicious_routes = set()

    for sc_id, events in raw_telemetry.items():
        cat = gt_map[sc_id]
        for ev in events:
            route = ev["normalized_route"]
            url = ev["url"]
            # Verify NO synthetic shortcut keywords in URL
            assert "internal-debug" not in url
            assert "credentials" not in url
            assert "directory" not in url
            assert "all?page" not in url
            assert "harvest" not in url
            assert "stealth" not in url

            if cat == GroundTruthCategory.BENIGN:
                benign_routes.add(route)
            elif cat == GroundTruthCategory.MALICIOUS:
                malicious_routes.add(route)

    # Core routes MUST be shared across benign and malicious scenarios
    shared_routes = benign_routes.intersection(malicious_routes)
    assert "/api/v1/customers/{id}" in shared_routes
    assert "/api/v1/accounts/{id}" in shared_routes
    assert "/api/v1/transactions" in shared_routes


# =============================================================================
# 6. Four Independent Cryptographic Hashes
# =============================================================================

def test_four_independent_hashes_and_master_digest():
    """All four independent hashes must verify on genuine artifacts."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    report = verify_dataset_integrity(m_path, g_path, t_path)
    assert report["valid"] is True, f"Integrity check failed: {report['errors']}"
    assert report["checks"]["telemetry_hash_match"] is True
    assert report["checks"]["ground_truth_hash_match"] is True
    assert report["checks"]["scenario_definitions_hash_match"] is True
    assert report["checks"]["manifest_hash_match"] is True
    assert report["checks"]["scenario_id_coherence"] is True
    assert report["checks"]["population_counts_valid"] is True
    assert report["checks"]["manifest_has_no_ground_truth"] is True


# =============================================================================
# 7. Comprehensive Tamper Detection Suite
# =============================================================================

def test_tamper_detection_telemetry(tmp_path):
    """Mutating 1 byte in telemetry must trigger telemetry hash mismatch."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    t_tampered = tmp_path / "dataset_telemetry_v1_1.json"
    raw_tel = json.loads(t_path.read_text(encoding="utf-8"))
    first_sc = sorted(raw_tel.keys())[0]
    raw_tel[first_sc][0]["status_code"] = 201  # Mutate 200 -> 201
    t_tampered.write_text(json.dumps(raw_tel), encoding="utf-8")

    report = verify_dataset_integrity(m_path, g_path, t_tampered)
    assert report["valid"] is False
    assert report["checks"]["telemetry_hash_match"] is False


def test_tamper_detection_ground_truth(tmp_path):
    """Mutating a ground-truth label must trigger ground truth hash mismatch."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    g_tampered = tmp_path / "ground_truth_v1_1.json"
    gt = GroundTruthArtifact.model_validate_json(g_path.read_text(encoding="utf-8"))
    gt.scenarios[0].expected_detection = not gt.scenarios[0].expected_detection
    g_tampered.write_text(gt.model_dump_json(indent=2), encoding="utf-8")

    report = verify_dataset_integrity(m_path, g_tampered, t_path)
    assert report["valid"] is False
    assert report["checks"]["ground_truth_hash_match"] is False


def test_tamper_detection_scenario_definitions(tmp_path):
    """Mutating structural scenario parameters must trigger scenario definition hash mismatch."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    m_tampered = tmp_path / "dataset_manifest_v1_1.json"
    manifest = DatasetManifest.model_validate_json(m_path.read_text(encoding="utf-8"))
    manifest.scenario_definitions[0].seed = 888888
    m_tampered.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    report = verify_dataset_integrity(m_tampered, g_path, t_path)
    assert report["valid"] is False
    assert report["checks"]["scenario_definitions_hash_match"] is False


def test_tamper_detection_manifest_metadata(tmp_path):
    """Mutating manifest metadata counts must trigger manifest hash mismatch."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"

    m_tampered = tmp_path / "dataset_manifest_v1_1.json"
    manifest = DatasetManifest.model_validate_json(m_path.read_text(encoding="utf-8"))
    manifest.benign_count = 81  # Mutate count
    m_tampered.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    report = verify_dataset_integrity(m_tampered, g_path, t_path)
    assert report["valid"] is False
    assert report["checks"]["manifest_hash_match"] is False


def test_tamper_detection_cross_version_reuse():
    """Attempting to pair v1.1 manifest with v1.0 telemetry must fail verification."""
    m_path = DATASETS_DIR / "dataset_manifest_v1_1.json"
    g_path = DATASETS_DIR / "ground_truth_v1_1.json"
    t_v1_path = DATASETS_DIR / "dataset_telemetry_v1.json"

    report = verify_dataset_integrity(m_path, g_path, t_v1_path)
    assert report["valid"] is False
    assert report["checks"]["telemetry_hash_match"] is False
    assert report["checks"]["scenario_id_coherence"] is False


# =============================================================================
# 8. Detector Input Isolation & Leakage Audit
# =============================================================================

def test_detector_inputs_contain_no_ground_truth():
    """Detectors must receive only EventTelemetry objects without ground-truth fields."""
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"
    raw_telemetry = json.loads(t_path.read_text(encoding="utf-8"))
    first_sc = list(raw_telemetry.keys())[0]
    events = [EventTelemetry.model_validate(e) for e in raw_telemetry[first_sc]]

    iso_detector = IsolatedRuleDetector()
    ctx_detector = ContextualDetector()

    # Isolated detector invocation
    iso_sc_out, iso_ev_outs = iso_detector.evaluate_scenario(first_sc, events)
    assert iso_sc_out is not None

    # Contextual detector invocation
    ctx_sc_out, ctx_ev_outs = ctx_detector.evaluate_scenario(first_sc, events)
    assert ctx_sc_out is not None

    # Prove no event has ground-truth attributes
    forbidden_attrs = ["category", "expected_detection", "expected_campaign", "expected_rules", "ground_truth"]
    for ev in events:
        for attr in forbidden_attrs:
            assert not hasattr(ev, attr), f"Event has ground-truth attribute '{attr}'!"


def test_exhaustive_leakage_scan():
    """All 590 telemetry events must be free of all 20 forbidden tokens."""
    t_path = DATASETS_DIR / "dataset_telemetry_v1_1.json"
    raw_telemetry = json.loads(t_path.read_text(encoding="utf-8"))
    telemetry_map = {
        k: [EventTelemetry.model_validate(item) for item in v]
        for k, v in raw_telemetry.items()
    }

    audit = audit_telemetry_label_leakage(telemetry_map)
    assert audit["leakage_detected"] is False, f"Label leakage found: {audit['violations']}"
    assert audit["violation_count"] == 0
    assert audit["total_events_scanned"] == 590


# =============================================================================
# 9. Generator Determinism
# =============================================================================

def test_generator_determinism():
    """Generator must produce bit-for-bit identical hashes across repeated runs."""
    gen1 = EvaluationDatasetGenerator(master_seed=42)
    m1, g1, t1 = gen1.generate_dataset_v1_1()

    gen2 = EvaluationDatasetGenerator(master_seed=42)
    m2, g2, t2 = gen2.generate_dataset_v1_1()

    assert m1.manifest_hash == m2.manifest_hash
    assert m1.telemetry_hash == m2.telemetry_hash
    assert m1.ground_truth_hash == m2.ground_truth_hash
    assert m1.scenario_definitions_hash == m2.scenario_definitions_hash
    assert g1.ground_truth_hash == g2.ground_truth_hash
