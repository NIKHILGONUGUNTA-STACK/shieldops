"""Data models for Aegis behavioral ML anomaly detection and sequence modeling."""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SequenceStep(BaseModel):
    """Represents a single API invocation step in a user session."""
    method: str
    path: str
    status_code: int = 200
    timestamp: Optional[str] = None

    @property
    def endpoint_key(self) -> str:
        return f"{self.method.upper()} {self.path}"


class SessionTrace(BaseModel):
    """Represents an ordered chronological trace of API steps executed by a subject/session."""
    session_id: str
    subject_id: Optional[str] = None
    steps: List[SequenceStep] = Field(default_factory=list)


class TransitionEntry(BaseModel):
    """Represents a single directed transition between two endpoints."""
    from_endpoint: str
    to_endpoint: str
    count: int = 0
    probability: float = 0.0


class SequenceProfile(BaseModel):
    """Trained discrete Markov transition matrix and extracted workflow invariants."""
    name: str = "default_api_markov_profile"
    version: str = "1.0.0"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_sessions: int = 0
    total_transitions: int = 0
    endpoints: List[str] = Field(default_factory=list)
    # transition_matrix[from_endpoint][to_endpoint] -> probability
    transition_matrix: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    # raw transition counts
    transition_counts: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    # critical_funnels[target_endpoint] -> list of mandatory/high-prob predecessor endpoints
    critical_funnels: Dict[str, List[str]] = Field(default_factory=dict)
    anomaly_threshold: float = 6.0


class TransitionViolation(BaseModel):
    """Details of a low-probability or impossible transition in a sequence."""
    from_endpoint: str
    to_endpoint: str
    probability: float
    neg_log_likelihood: float
    description: str


class SequenceAnomalyReport(BaseModel):
    """Evaluation verdict for an API session traversal sequence."""
    session_id: str
    subject_id: Optional[str] = None
    sequence_length: int
    anomaly_score: float
    is_anomalous: bool
    threshold: float
    violations: List[TransitionViolation] = Field(default_factory=list)
    lowest_probability_step: Optional[TransitionViolation] = None
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class OutlierMetricSummary(BaseModel):
    """Statistical summary of a single tracked metric for an endpoint."""
    metric_name: str
    count: int = 0
    mean: float = 0.0
    variance: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0


class OutlierEvaluationResult(BaseModel):
    """Real-time statistical evaluation result for a single API transaction."""
    endpoint: str
    payload_bytes: int
    latency_ms: float
    payload_z_score: float = 0.0
    latency_z_score: float = 0.0
    max_z_score: float = 0.0
    outlier_score: float = 0.0  # Normalized continuous score [0.0, 1.0]
    is_outlier: bool = False
    outlier_type: Optional[str] = None  # VOLUMETRIC_EXFILTRATION, LATENCY_DEGRADATION, or COMBO
    details: Dict[str, Any] = Field(default_factory=dict)
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class OutlierBaselineProfile(BaseModel):
    """Persisted statistical baseline profiles for all known API endpoints."""
    name: str = "production_outlier_profile"
    version: str = "1.0.0"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_observations: int = 0
    z_threshold: float = 3.5
    # endpoints[endpoint_key][metric_name] -> OutlierMetricSummary
    endpoints: Dict[str, Dict[str, OutlierMetricSummary]] = Field(default_factory=dict)

