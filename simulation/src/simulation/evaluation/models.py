"""Models and Data Structures for Phase 7.3.6 Research Evaluation Engine.

Provides strictly isolated ground truth, telemetry representations, evaluation
metrics, statistical intervals, and manifest definitions.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
import math
from typing import Any, Callable, Dict, List, Optional
from pydantic import BaseModel, Field


class GroundTruthCategory(str, Enum):
    """Ground truth category of an evaluation scenario."""

    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"
    AMBIGUOUS = "AMBIGUOUS"
    INCOMPLETE_EVIDENCE = "INCOMPLETE_EVIDENCE"


class EvaluationUnit(str, Enum):
    """Mandatory evaluation unit dimension to prevent metric conflation."""

    EVENT_LEVEL = "EVENT_LEVEL"
    SCENARIO_LEVEL = "SCENARIO_LEVEL"
    CAMPAIGN_LEVEL = "CAMPAIGN_LEVEL"
    UNCERTAINTY_HANDLING = "UNCERTAINTY_HANDLING"


class EvaluationMode(str, Enum):
    """Detection configuration mode."""

    ISOLATED_RULES = "ISOLATED_RULES"
    CONTEXTUAL_CORRELATION = "CONTEXTUAL_CORRELATION"
    ABLATION_NO_IDENTITY = "ABLATION_NO_IDENTITY"
    ABLATION_NO_TENANT = "ABLATION_NO_TENANT"
    ABLATION_NO_OWNERSHIP = "ABLATION_NO_OWNERSHIP"
    ABLATION_NO_SENSITIVITY = "ABLATION_NO_SENSITIVITY"
    ABLATION_NO_AUTH_OUTCOME = "ABLATION_NO_AUTH_OUTCOME"
    ABLATION_NO_TEMPORAL = "ABLATION_NO_TEMPORAL"
    ABLATION_NO_CAMPAIGN = "ABLATION_NO_CAMPAIGN"


class ClassificationOutcome(str, Enum):
    """Confusion matrix outcome classification."""

    TP = "TP"  # Correctly flagged malicious
    TN = "TN"  # Correctly passed benign
    FP = "FP"  # Falsely flagged benign
    FN = "FN"  # Missed malicious
    UNCERTAIN_CORRECT = "UNCERTAIN_CORRECT"  # Ambiguous/Incomplete appropriately flagged as uncertain
    UNCERTAIN_INCORRECT = "UNCERTAIN_INCORRECT"  # Ambiguous/Incomplete misclassified as safe/benign


class ConfidenceInterval(BaseModel):
    """Statistical confidence interval (e.g., Wilson score or Bootstrap)."""

    point_estimate: float = 0.0
    lower: float = 0.0
    upper: float = 0.0
    confidence_level: float = 0.95
    method: str = "wilson"  # 'wilson' or 'bootstrap'
    sample_size: int = 0


class LatencyStats(BaseModel):
    """Detection latency distribution in milliseconds."""

    sample_count: int = 0
    mean_ms: float = 0.0
    median_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0


class ConfusionMatrix(BaseModel):
    """Confusion matrix with explicit zero-denominator safety."""

    total_samples: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    uncertain_handled: int = 0
    uncertain_misclassified: int = 0


class MetricReport(BaseModel):
    """Comprehensive performance metrics with confidence intervals."""

    confusion_matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0
    false_discovery_rate: float = 0.0  # Explicit FDR = FP / (TP + FP) to distinguish from FPR = FP / (FP + TN)
    false_negative_rate: float = 0.0
    specificity: float = 0.0
    uncertainty_rate: float = 0.0
    sample_size: int = 0

    ci_precision: Optional[ConfidenceInterval] = None
    ci_recall: Optional[ConfidenceInterval] = None
    ci_f1: Optional[ConfidenceInterval] = None
    ci_fpr: Optional[ConfidenceInterval] = None
    ci_fdr: Optional[ConfidenceInterval] = None

    latency: LatencyStats = Field(default_factory=LatencyStats)
    throughput_eps: float = 0.0


class UncertaintyReport(BaseModel):
    """Explicit disposition metrics for ambiguous and incomplete evaluation populations."""

    total_samples: int = 50
    ambiguous_count: int = 30
    incomplete_count: int = 20
    abstained_uncertain: int = 0
    flagged_malicious: int = 0
    passed_benign: int = 0
    abstention_rate: float = 0.0
    over_escalation_rate: float = 0.0
    under_investigation_rate: float = 0.0
    ci_abstention: Optional[ConfidenceInterval] = None
    disposition_breakdown: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class PopulationAccounting(BaseModel):
    """Full-population accounting across primary binary and secondary ambiguous/incomplete scenarios."""

    total_dataset_size: int = 200
    primary_binary_evaluated: int = 150
    binary_benign_count: int = 80
    binary_malicious_count: int = 70
    ambiguous_evaluated: int = 30
    incomplete_evaluated: int = 20
    binary_coverage_ratio: float = 0.75
    accounting_reconciled: bool = True


class PairedComparisonResult(BaseModel):
    """Exact paired statistical comparison between Isolated Rules and Contextual Detection."""

    test_name: str = "Exact Two-Sided McNemar Test & Paired Scenario Bootstrap"
    sample_size: int = 150
    both_correct_a: int = 0
    isolated_correct_contextual_incorrect_b: int = 0
    isolated_incorrect_contextual_correct_c: int = 0
    both_incorrect_d: int = 0
    discordant_pairs_total: int = 0
    contingency_matrix: List[List[int]] = Field(default_factory=list)
    p_value_exact: float = 1.0
    statistically_significant: bool = False
    alpha_level: float = 0.05
    odds_ratio: float = 0.0
    delta_accuracy: float = 0.0
    bootstrap_resamples: int = 2000
    delta_precision: float = 0.0
    ci_delta_precision: Optional[ConfidenceInterval] = None
    delta_recall: float = 0.0
    ci_delta_recall: Optional[ConfidenceInterval] = None
    delta_f1: float = 0.0
    ci_delta_f1: Optional[ConfidenceInterval] = None
    delta_fpr: float = 0.0
    ci_delta_fpr: Optional[ConfidenceInterval] = None


class EventTelemetry(BaseModel):
    """Normalized API event telemetry fed to detection engines.

    NOTE: Contains ZERO scenario labels, scenario names, or ground truth.
    """

    event_id: str
    scenario_id: str
    timestamp_epoch_ms: int
    http_method: str
    url: str
    normalized_route: str
    status_code: int
    user_id: Optional[str] = None
    auth_subject: Optional[str] = None
    tenant_id: Optional[str] = None
    source_ip: str = "127.0.0.1"
    customer_id: Optional[str] = None
    resource_owner_id: Optional[str] = None
    sensitivity: str = "UNKNOWN"
    observed_fields: List[str] = Field(default_factory=list)
    page_number: Optional[int] = None
    page_size: Optional[int] = None
    response_bytes: int = 0
    correlation_id: str = ""


class ScenarioGroundTruth(BaseModel):
    """Separately maintained ground-truth definition for a scenario execution."""

    scenario_id: str
    scenario_family: str
    scenario_name: str
    category: GroundTruthCategory
    expected_detection: bool
    expected_campaign: bool
    expected_rules: List[str] = Field(default_factory=list)
    seed: int
    num_requests: int
    num_identities: int
    num_tenants: int
    num_resources: int
    duration_seconds: float
    description: str


class DetectionOutput(BaseModel):
    """Independently recorded detection outcome for an evaluation unit."""

    unit: EvaluationUnit
    unit_id: str  # event_id, scenario_id, or campaign_id
    detected: bool
    is_uncertain: bool = False
    triggered_rules: List[str] = Field(default_factory=list)
    campaign_identified: bool = False
    risk_score: float = 0.0
    confidence_score: float = 0.0
    explanation: str = ""
    processing_latency_ms: float = 0.0


class UnitEvaluation(BaseModel):
    """Paired evaluation of ground truth against detector output."""

    unit: EvaluationUnit
    unit_id: str
    ground_truth_category: GroundTruthCategory
    expected_detection: bool
    actual_detection: bool
    is_uncertain: bool
    classification: ClassificationOutcome
    triggered_rules: List[str]
    campaign_identified: bool
    explanation: str


class ScenarioDefinition(BaseModel):
    """Structural scenario parameters with ZERO ground-truth labels or expected outcomes."""

    scenario_id: str
    seed: int
    num_requests: int
    num_identities: int
    num_tenants: int
    num_resources: int
    duration_seconds: float


class GroundTruthArtifact(BaseModel):
    """Independently persisted ground-truth artifact strictly segregated from detector inputs."""

    dataset_id: str
    version: str
    created_at: str
    ground_truth_hash: str = ""
    total_scenarios: int
    population_distribution: Dict[str, int] = Field(default_factory=dict)
    scenarios: List[ScenarioGroundTruth] = Field(default_factory=list)

    def calculate_hash(self) -> str:
        return compute_canonical_ground_truth_hash(self.scenarios)


class DatasetManifest(BaseModel):
    """Versioned and verifiable dataset manifest."""

    dataset_id: str
    version: str
    created_at: str
    manifest_hash: str = ""
    telemetry_hash: str = ""
    ground_truth_hash: str = ""
    scenario_definitions_hash: str = ""
    total_scenarios: int
    benign_count: int
    malicious_count: int
    ambiguous_count: int
    incomplete_count: int
    # Preserved for v1.0 backward compatibility
    scenarios: List[ScenarioGroundTruth] = Field(default_factory=list)
    # Segregated v1.1 structural definitions (ZERO ground-truth labels)
    scenario_definitions: List[ScenarioDefinition] = Field(default_factory=list)

    def calculate_hash(self) -> str:
        """Legacy v1.0 hash for backward compatibility."""
        data_to_hash = [
            {
                "id": s.scenario_id,
                "cat": s.category.value,
                "exp": s.expected_detection,
                "seed": s.seed,
                "reqs": s.num_requests,
            }
            for s in sorted(self.scenarios, key=lambda x: x.scenario_id)
        ]
        serialized = json.dumps(data_to_hash, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def calculate_ground_truth_hash(self) -> str:
        """Calculates deterministic SHA-256 hash strictly across ground-truth classifications."""
        return compute_canonical_ground_truth_hash(self.scenarios)

    def calculate_scenario_definitions_hash(self) -> str:
        """Calculates deterministic SHA-256 hash of structural scenario definitions."""
        if self.scenario_definitions:
            return compute_canonical_scenario_definitions_hash(self.scenario_definitions)
        # Fallback for v1.0 scenarios list
        data_to_hash = [
            {
                "id": s.scenario_id,
                "seed": s.seed,
                "num_requests": s.num_requests,
                "num_identities": s.num_identities,
                "num_tenants": s.num_tenants,
                "num_resources": s.num_resources,
                "duration_seconds": s.duration_seconds,
            }
            for s in sorted(self.scenarios, key=lambda x: x.scenario_id)
        ]
        serialized = json.dumps(data_to_hash, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def calculate_manifest_hash(self) -> str:
        """Calculates deterministic SHA-256 hash binding manifest metadata and independent sub-hashes.

        Non-circular: binds telemetry_hash, ground_truth_hash, and scenario_definitions_hash.
        """
        data_to_hash = {
            "dataset_id": self.dataset_id,
            "version": self.version,
            "total_scenarios": self.total_scenarios,
            "benign_count": self.benign_count,
            "malicious_count": self.malicious_count,
            "ambiguous_count": self.ambiguous_count,
            "incomplete_count": self.incomplete_count,
            "telemetry_hash": self.telemetry_hash,
            "ground_truth_hash": self.ground_truth_hash or self.calculate_ground_truth_hash(),
            "scenario_definitions_hash": self.scenario_definitions_hash or self.calculate_scenario_definitions_hash(),
        }
        serialized = json.dumps(data_to_hash, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_canonical_telemetry_hash(telemetry_map: Dict[str, List[EventTelemetry]]) -> str:
    """Computes deterministic SHA-256 hash of canonical telemetry events across all scenarios."""
    canonical_data = {
        sc_id: [e.model_dump() for e in events]
        for sc_id, events in sorted(telemetry_map.items())
    }
    serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_canonical_ground_truth_hash(scenarios: List[ScenarioGroundTruth]) -> str:
    """Computes deterministic SHA-256 hash strictly across ground-truth classifications."""
    data_to_hash = [
        {
            "id": s.scenario_id,
            "category": s.category.value,
            "expected_detection": s.expected_detection,
            "expected_campaign": s.expected_campaign,
            "expected_rules": sorted(s.expected_rules),
        }
        for s in sorted(scenarios, key=lambda x: x.scenario_id)
    ]
    serialized = json.dumps(data_to_hash, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def compute_canonical_scenario_definitions_hash(definitions: List[ScenarioDefinition]) -> str:
    """Computes deterministic SHA-256 hash of structural scenario definitions."""
    data_to_hash = [
        {
            "id": s.scenario_id,
            "seed": s.seed,
            "num_requests": s.num_requests,
            "num_identities": s.num_identities,
            "num_tenants": s.num_tenants,
            "num_resources": s.num_resources,
            "duration_seconds": s.duration_seconds,
        }
        for s in sorted(definitions, key=lambda x: x.scenario_id)
    ]
    serialized = json.dumps(data_to_hash, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
