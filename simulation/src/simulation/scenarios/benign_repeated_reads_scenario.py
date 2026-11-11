"""Legitimate Repeated Reads Scenario (SCEN-BENIGN-02).

Simulates high-frequency legitimate customer reads of authorized, owned resources.
Used to evaluate false-positive resistance:
- Verifies that repeated reads of the SAME resource owned by the caller do NOT trigger
  bulk extraction (RULE-BULK-EXTRACT-01) or BOLA alarms.
- Validates the zero false-positive invariant for legitimate high-frequency client apps.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any
import uuid

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import (
    GatewayClient,
    GatewayResponse,
)
from simulation.config import SimulationConfig
from simulation.models import (
    ExecutionStatus,
    RequestResult,
    RunManifest,
    ScenarioMetadata,
    ScenarioSummary,
    normalize_gateway_route,
)
from simulation.scenarios.base import BaseScenario

log = logging.getLogger(__name__)


class BenignRepeatedReadsScenario(BaseScenario):
    """Executes SCEN-BENIGN-02: Legitimate repeated reads within authorized customer workflow."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        repetitions: int = 5,
    ) -> None:
        super().__init__(metadata, config)
        self.repetitions = repetitions
        self.run_id = str(uuid.uuid4())
        self.recorded_requests: list[RequestResult] = []

    def _record_response(
        self,
        summary: ScenarioSummary,
        response: GatewayResponse,
        identity_label: str,
    ) -> None:
        norm_route = normalize_gateway_route(response.url)
        result = RequestResult(
            correlation_id=response.correlation_id,
            http_method=response.http_method,
            url=response.url,
            normalized_route=norm_route,
            identity_label=identity_label,
            status_code=response.status_code,
            duration_ms=response.duration_ms,
            is_success=response.is_success,
            error_message=None if response.is_success else f"HTTP {response.status_code} ({identity_label})",
        )
        self.recorded_requests.append(result)
        summary.record_request(result)

    async def execute(
        self,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
    ) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        try:
            alex_pass = self.config.require_password("alex.morgan")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            # Repeatedly query the customer's own profile and accounts
            for i in range(self.repetitions):
                log.info("[%s] Repetition %d/%d: Querying own customer profile", self.metadata.id, i + 1, self.repetitions)
                resp_profile = await gateway.get(f"/api/v1/customers/{alex_id}", token=alex_token)
                self._record_response(summary, resp_profile, "alex.morgan")

                resp_acc = await gateway.get("/api/v1/accounts", token=alex_token)
                self._record_response(summary, resp_acc, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
            log.error("[%s] Execution error: %s", self.metadata.id, e, exc_info=True)
        finally:
            summary.finished_at = datetime.now(timezone.utc)
            summary.run_manifest = RunManifest(
                run_id=self.run_id,
                scenario_id=self.metadata.id,
                dry_run=False,
                started_at=summary.started_at,
                finished_at=summary.finished_at,
                execution_outcome=summary.status.value,
                total_requests=summary.total_requests,
                successful_requests=summary.successful_requests,
                failed_requests=summary.failed_requests,
                status_distribution=summary.status_distribution,
                requests=self.recorded_requests,
            )

        return summary
