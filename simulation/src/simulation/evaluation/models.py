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

    confusion_matrix: ConfusionMatrix
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    specificity: float = 0.0
    uncertainty_rate: float = 0.0

    ci_precision: Optional[ConfidenceInterval] = None
    ci_recall: Optional[ConfidenceInterval] = None
    ci_f1: Optional[ConfidenceInterval] = None
    ci_fpr: Optional[ConfidenceInterval] = None

    latency: LatencyStats = Field(default_factory=LatencyStats)
    throughput_eps: float = 0.0


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


class DatasetManifest(BaseModel):
    """Versioned and verifiable dataset manifest."""

    dataset_id: str
    version: str
    created_at: str
    manifest_hash: str = ""
    total_scenarios: int
    benign_count: int
    malicious_count: int
    ambiguous_count: int
    incomplete_count: int
    scenarios: List[ScenarioGroundTruth] = Field(default_factory=list)

    def calculate_hash(self) -> str:
        """Calculates deterministic SHA-256 hash across sorted scenario entries."""
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
