"""Core domain and scenario models for Aegis simulation framework."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ScenarioCategory(str, Enum):
    """Categorization of simulation workflows and attack vectors."""

    BENIGN = "BENIGN"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    BOLA = "BOLA"
    PROBING = "PROBING"
    INJECTION = "INJECTION"
    RATE_ABUSE = "RATE_ABUSE"
    DATA_ACCESS = "DATA_ACCESS"
    MULTI_VECTOR = "MULTI_VECTOR"


class ExecutionStatus(str, Enum):
    """Execution status of a scenario or simulation run."""

    PLANNED = "PLANNED"
    NOT_STARTED = "NOT_STARTED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    SKIPPED = "SKIPPED"


class ExpectedOutcome(BaseModel):
    """Defines the expected defensive outcome of a simulation scenario."""

    expected_status_codes: list[int] = Field(
        default_factory=list,
        description="List of HTTP status codes expected from the scenario requests",
    )
    expected_detection_rules: list[str] = Field(
        default_factory=list,
        description="IDs of detection rules expected to fire (e.g. RULE-BOLA-01)",
    )
    expected_incident_severity: str | None = Field(
        default=None,
        description="Severity of incident expected to be generated (e.g. HIGH, CRITICAL)",
    )
    advisory_only: bool = Field(
        default=True,
        description="Confirms that detection is advisory and non-blocking",
    )


class ScenarioMetadata(BaseModel):
    """Static metadata describing a simulation scenario."""

    id: str = Field(..., description="Unique scenario identifier (e.g. SCEN-BOLA-01)")
    name: str = Field(..., description="Human-readable scenario name")
    description: str = Field(..., description="Detailed description of the workflow or attack vector")
    category: ScenarioCategory = Field(..., description="Vector category")
    target_services: list[str] = Field(default_factory=list, description="Downstream services impacted")
    expected_outcome: ExpectedOutcome = Field(default_factory=ExpectedOutcome)
    is_implemented: bool = Field(default=False, description="Whether the executable scenario is implemented")


class RequestResult(BaseModel):
    """Sanitized record of an individual request executed during a scenario.

    Strict Safety Invariant:
    Never captures authorization tokens, passwords, or raw request/response bodies.
    """

    correlation_id: str
    http_method: str
    url: str
    status_code: int
    duration_ms: float
    is_success: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: str | None = None


class ScenarioSummary(BaseModel):
    """Execution summary and metrics for a scenario."""

    scenario_id: str
    category: ScenarioCategory
    status: ExecutionStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    status_distribution: dict[int, int] = Field(default_factory=dict)
    expected_detection_rules: list[str] = Field(default_factory=list)
    execution_errors: list[str] = Field(default_factory=list)
    request_results: list[RequestResult] = Field(default_factory=list, exclude=True)

    def record_request(self, result: RequestResult) -> None:
        """Records a request result and updates aggregates."""
        self.request_results.append(result)
        self.total_requests += 1
        if result.is_success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1

        self.status_distribution[result.status_code] = (
            self.status_distribution.get(result.status_code, 0) + 1
        )
