"""BOLA Simulation Scenarios (SCEN-BOLA-01 and SCEN-BOLA-02).

Implements deterministic BOLA access and probing scenarios:
- SCEN-BOLA-01: Single Cross-Customer Unauthorized Access Attempt.
- SCEN-BOLA-02: Multi-Target BOLA Probing Campaign across distinct resources.
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


class BolaAttemptScenario(BaseScenario):
    """Executes SCEN-BOLA-01: Customer attempts unauthorized cross-owner resource access."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        victim_customer_id: str = "20000000-0000-4000-8000-000000000002",
        victim_account_id: str = "30000000-0000-4000-8000-000000000003",
    ) -> None:
        super().__init__(metadata, config)
        self.victim_customer_id = victim_customer_id
        self.victim_account_id = victim_account_id
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

            # Step 1: Benign self check to verify baseline connectivity
            alex_id = self.config.benign_flow.alex_customer_id
            resp_self = await gateway.get(f"/api/v1/customers/{alex_id}", token=alex_token)
            self._record_response(summary, resp_self, "alex.morgan")

            # Step 2: Attempt unauthorized access to victim customer profile
            log.info("[%s] Attempting cross-owner customer lookup for %s", self.metadata.id, self.victim_customer_id)
            resp_victim_cust = await gateway.get(f"/api/v1/customers/{self.victim_customer_id}", token=alex_token)
            self._record_response(summary, resp_victim_cust, "alex.morgan")

            # Step 3: Attempt unauthorized access to victim account details
            log.info("[%s] Attempting cross-owner account lookup for %s", self.metadata.id, self.victim_account_id)
            resp_victim_acc = await gateway.get(f"/api/v1/accounts/{self.victim_account_id}", token=alex_token)
            self._record_response(summary, resp_victim_acc, "alex.morgan")

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


class BolaProbeCampaignScenario(BaseScenario):
    """Executes SCEN-BOLA-02: Denied cross-owner access followed by sequential probing across accounts."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        probe_targets: list[str] | None = None,
    ) -> None:
        super().__init__(metadata, config)
        self.probe_targets = probe_targets or [
            "acc-victim-001",
            "acc-victim-002",
            "acc-victim-003",
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

            # Probe multiple targets sequentially to trip sliding-window campaign threshold
            for target in self.probe_targets:
                log.info("[%s] Probing target account %s", self.metadata.id, target)
                resp = await gateway.get(f"/api/v1/accounts/{target}", token=alex_token)
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
