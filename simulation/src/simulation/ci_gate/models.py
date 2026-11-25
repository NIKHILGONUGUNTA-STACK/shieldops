"""Data models and structures for the Aegis Shift-Left API Security CI/CD Gate."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    UNAUTHENTICATED_MUTATING_OPERATION = "UNAUTHENTICATED_MUTATING_OPERATION"
    UNAUTHENTICATED_ENDPOINT = "UNAUTHENTICATED_ENDPOINT"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SHADOW_ROUTE_DETECTED = "SHADOW_ROUTE_DETECTED"
    BREAKING_ENDPOINT_REMOVAL = "BREAKING_ENDPOINT_REMOVAL"
    BREAKING_PARAM_REQUIRED = "BREAKING_PARAM_REQUIRED"
    MISSING_OWNERSHIP_VALIDATION = "MISSING_OWNERSHIP_VALIDATION"
    INSECURE_PARAMETER_FORMAT = "INSECURE_PARAMETER_FORMAT"


class GateVerdict(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"


class GateFinding(BaseModel):
    id: str
    severity: Severity
    finding_type: FindingType
    method: str
    path: str
    message: str
    remediation: str
    breaking: bool = False
    details: Optional[Dict[str, Any]] = None


class OperationDiff(BaseModel):
    change_type: str  # ADDED, REMOVED, MODIFIED, UNCHANGED
    method: str
    path: str
    summary: Optional[str] = None
    breaking: bool = False
    details: List[str] = Field(default_factory=list)


class GateSummary(BaseModel):
    total_operations: int = 0
    authenticated_operations: int = 0
    unauthenticated_operations: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    breaking_count: int = 0
    posture_score: float = 100.0
    posture_delta: float = 0.0
    verdict: GateVerdict = GateVerdict.PASSED


class GateReport(BaseModel):
    spec_path: str
    spec_title: str
    spec_version: str
    gateway_connected: bool = False
    gateway_url: Optional[str] = None
    summary: GateSummary
    findings: List[GateFinding] = Field(default_factory=list)
    contract_diffs: List[OperationDiff] = Field(default_factory=list)
    evaluated_at: str
