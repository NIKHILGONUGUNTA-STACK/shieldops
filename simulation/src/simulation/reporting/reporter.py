"""Simulation execution reporting and metrics aggregation.

Generates structured JSON reports for SOC analysts, ensuring strict redaction
of credentials, bearer tokens, and sensitive customer payloads.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any
from pydantic import BaseModel, Field

from simulation.models import (
    ExecutionStatus,
    RunManifest,
    ScenarioSummary,
)

log = logging.getLogger(__name__)


class SimulationRunReport(BaseModel):
    """Aggregated report of an entire simulation execution run."""

    environment_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    total_scenarios: int = 0
    scenarios_passed: int = 0
    scenarios_failed: int = 0
    scenarios_planned: int = 0
    total_requests: int = 0
    total_successful_requests: int = 0
    total_failed_requests: int = 0
    overall_status_distribution: dict[int, int] = Field(default_factory=dict)
    scenarios: list[ScenarioSummary] = Field(default_factory=list)
    manifests: list[RunManifest] = Field(default_factory=list)


class ScenarioReporter:
    """Manages report compilation, aggregation, and safe JSON serialization."""

    def __init__(self, environment_id: str = "local-dev") -> None:
        self.report = SimulationRunReport(environment_id=environment_id)

    def record_scenario(self, summary: ScenarioSummary) -> None:
        """Appends a scenario summary and updates run aggregates."""
        self.report.scenarios.append(summary)
        if summary.run_manifest:
            self.report.manifests.append(summary.run_manifest)
        self.report.total_scenarios += 1

        if summary.status == ExecutionStatus.SUCCESS:
            self.report.scenarios_passed += 1
        elif summary.status == ExecutionStatus.FAILURE:
            self.report.scenarios_failed += 1
        elif summary.status in (ExecutionStatus.PLANNED, ExecutionStatus.NOT_STARTED):
            self.report.scenarios_planned += 1

        self.report.total_requests += summary.total_requests
        self.report.total_successful_requests += summary.successful_requests
        self.report.total_failed_requests += summary.failed_requests

        for code, count in summary.status_distribution.items():
            self.report.overall_status_distribution[code] = (
                self.report.overall_status_distribution.get(code, 0) + count
            )

    def finalize(self) -> SimulationRunReport:
        """Sets the finished timestamp and returns the report model."""
        if not self.report.finished_at:
            self.report.finished_at = datetime.now(timezone.utc)
        return self.report

    def to_json(self, indent: int = 2) -> str:
        """Serializes the report to JSON, verifying safety and absence of credentials."""
        self.finalize()
        raw_json = self.report.model_dump_json(indent=indent)

        # Defensive Safety Assertion: verify zero tokens or password leaks
        forbidden_markers = ["bearer ", "eyjh", "password", "client_secret"]
        lower_json = raw_json.lower()
        for marker in forbidden_markers:
            if marker in lower_json:
                raise ValueError(
                    f"Safety Violation: Report serialization contains forbidden sensitive marker '{marker}'"
                )

        return raw_json

    @staticmethod
    def save_manifest(manifest: RunManifest, output_path: str) -> str:
        """Serializes and saves a RunManifest to disk with strict safety assertions."""
        from pathlib import Path
        raw_json = manifest.model_dump_json(indent=2)
        forbidden_markers = ["bearer ", "eyjh", "password", "client_secret"]
        lower_json = raw_json.lower()
        for marker in forbidden_markers:
            if marker in lower_json:
                raise ValueError(
                    f"Safety Violation: Manifest serialization contains forbidden sensitive marker '{marker}'"
                )
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw_json, encoding="utf-8")
        return str(path)

    def to_dict(self) -> dict[str, Any]:
        """Returns the report as a native dictionary."""
        self.finalize()
        return json.loads(self.to_json())

