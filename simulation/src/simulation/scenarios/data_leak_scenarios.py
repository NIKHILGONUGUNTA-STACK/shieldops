"""Data Leakage and Exfiltration Simulation Scenarios.

Implements:
- SCEN-DATA-LEAK-01: Sensitive Data Exposure (Confidential customer data access).
- SCEN-BULK-EXTRACT-01: Excessive Data Access and Bulk Extraction across >= 3 distinct resources.
- SCEN-EXFIL-01: Multi-Stage Exfiltration Campaign (Reconnaissance -> BOLA Probing -> Data Extraction).
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


class DataLeakScenario(BaseScenario):
    """Executes SCEN-DATA-LEAK-01: Unexpected confidential field exposure on sensitive endpoints."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        target_customer_id: str = "cust-sam-002",
    ) -> None:
        super().__init__(metadata, config)
        self.target_customer_id = target_customer_id
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

            # Step 1: Request sensitive customer profile without ownership
            log.info("[%s] Querying sensitive customer details for %s", self.metadata.id, self.target_customer_id)
            resp = await gateway.get(f"/api/v1/customers/{self.target_customer_id}", token=alex_token)
            self._record_response(summary, resp, "alex.morgan")

            # Step 2: Request sensitive account balance endpoint
            resp_bal = await gateway.get(f"/api/v1/accounts/acc-{self.target_customer_id}/balance", token=alex_token)
            self._record_response(summary, resp_bal, "alex.morgan")

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


class BulkExtractScenario(BaseScenario):
    """Executes SCEN-BULK-EXTRACT-01: Iterative reads across >= 3 customer resources."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        resource_ids: list[str] | None = None,
    ) -> None:
        super().__init__(metadata, config)
        self.resource_ids = resource_ids or [
            "cust-harv-001",
            "cust-harv-002",
            "cust-harv-003",
            "cust-harv-004",
        ]
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

            # Query >= 3 distinct resources in rapid sequence within sliding window
            for res_id in self.resource_ids:
                log.info("[%s] Extracting customer resource %s", self.metadata.id, res_id)
                resp = await gateway.get(f"/api/v1/customers/{res_id}", token=alex_token)
                self._record_response(summary, resp, "alex.morgan")

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


class MultiStageExfilScenario(BaseScenario):
    """Executes SCEN-EXFIL-01: Multi-stage Reconnaissance -> BOLA Probing -> Data Extraction Campaign."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
    ) -> None:
        super().__init__(metadata, config)
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

            # Stage 1: Reconnaissance (probing unmapped endpoints/actuators)
            log.info("[%s] Stage 1: Probing non-existent / admin / actuator paths", self.metadata.id)
            recon_paths = ["/actuator/env", "/api/v1/admin/internal", "/api/v1/swagger-config"]
            for path in recon_paths:
                resp = await gateway.get(path, token=alex_token)
                self._record_response(summary, resp, "alex.morgan")

            # Stage 2: BOLA Probing (cross-owner account probes)
            log.info("[%s] Stage 2: Probing cross-owner account IDs", self.metadata.id)
            bola_targets = ["acc-probe-x1", "acc-probe-x2"]
            for target in bola_targets:
                resp = await gateway.get(f"/api/v1/accounts/{target}", token=alex_token)
                self._record_response(summary, resp, "alex.morgan")

            # Stage 3: Data Extraction (bulk customer queries)
            log.info("[%s] Stage 3: Bulk data extraction across customer profiles", self.metadata.id)
            exfil_targets = ["cust-harvest-a", "cust-harvest-b", "cust-harvest-c"]
            for target in exfil_targets:
                resp = await gateway.get(f"/api/v1/customers/{target}", token=alex_token)
                self._record_response(summary, resp, "alex.morgan")

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
