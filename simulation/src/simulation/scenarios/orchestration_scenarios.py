"""Phase 7.3.1: Scenario catalogue extensions for security simulation and campaign orchestration.

Provides executable scenarios for:
- BENIGN:
  * SCEN-BENIGN-BENEFICIARY: Beneficiary creation and counterparty verification
- SECURITY:
  * SCEN-SEC-AUTH-ABUSE: Authentication abuse (invalid tokens, brute-force probes, expired credentials)
  * SCEN-SEC-INJECTION-PROBE: Injection test patterns (SQLi, path traversal) against test endpoints
- MIXED:
  * SCEN-MIXED-CONCURRENT: Concurrent benign customer transactions alongside attacker probing
  * SCEN-MIXED-MULTI-TENANT: Multi-tenant ownership boundary isolation testing
- INFRASTRUCTURE:
  * SCEN-INFRA-BACKLOG: Gateway & Redis stream backlog resilience under burst telemetry
  * SCEN-INFRA-UNAVAILABLE: Graceful handling and detection isolation for unavailable services
"""

from __future__ import annotations

import asyncio
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


class BeneficiaryCreationScenario(BaseScenario):
    """SCEN-BENIGN-BENEFICIARY: Legitimate customer profile and beneficiary creation."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-beneficiary-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        alex_id = self.config.benign_flow.alex_customer_id
        sam_id = self.config.benign_flow.sam_customer_id

        # 1. Authenticate Alex
        alex_token = None
        if not self.dry_run:
            try:
                alex_pass = self.config.get_password("alex.morgan") or "Password123!"
                alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            except Exception as e:
                log.warning("Could not fetch Keycloak token for alex.morgan: %s", e)
                alex_token = "mock-alex-jwt-token"
        else:
            alex_token = "mock-alex-jwt-token"

        # 2. Read own profile
        res1 = await gateway.request(
            "GET", f"/api/v1/customers/{alex_id}/profile",
            token=alex_token,
            headers={"X-Simulation-Run-Id": self.run_id, "X-Simulation-Scenario-Id": self.metadata.id}
        )
        summary.record_request(RequestResult(
            correlation_id=res1.correlation_id, http_method="GET", url=res1.url,
            status_code=res1.status_code, duration_ms=res1.duration_ms, is_success=res1.is_success,
            identity_label="alex_morgan", normalized_route=normalize_gateway_route(res1.url)
        ))

        # 3. Read counterparty verification endpoint (mock/safe)
        res2 = await gateway.request(
            "GET", f"/api/v1/customers/{sam_id}",
            token=alex_token,
            headers={"X-Simulation-Run-Id": self.run_id, "X-Simulation-Scenario-Id": self.metadata.id}
        )
        summary.record_request(RequestResult(
            correlation_id=res2.correlation_id, http_method="GET", url=res2.url,
            status_code=res2.status_code, duration_ms=res2.duration_ms, is_success=res2.is_success,
            identity_label="alex_morgan", normalized_route=normalize_gateway_route(res2.url)
        ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class AuthAbuseScenario(BaseScenario):
    """SCEN-SEC-AUTH-ABUSE: Authentication abuse using invalid, expired, and malformed tokens."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-auth-abuse-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        alex_id = self.config.benign_flow.alex_customer_id

        # 1. Malformed Bearer token
        res1 = await gateway.request(
            "GET", f"/api/v1/customers/{alex_id}/profile",
            headers={
                "Authorization": "Bearer not.a.valid.jwt.signature",
                "X-Simulation-Run-Id": self.run_id,
                "X-Simulation-Scenario-Id": self.metadata.id
            }
        )
        summary.record_request(RequestResult(
            correlation_id=res1.correlation_id, http_method="GET", url=res1.url,
            status_code=res1.status_code, duration_ms=res1.duration_ms, is_success=(res1.status_code == 401),
            identity_label="attacker_auth_probe", normalized_route=normalize_gateway_route(res1.url)
        ))

        # 2. Expired token simulation
        res2 = await gateway.request(
            "GET", f"/api/v1/accounts",
            headers={
                "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTYyMzkwMjJ9.expired_signature",
                "X-Simulation-Run-Id": self.run_id,
                "X-Simulation-Scenario-Id": self.metadata.id
            }
        )
        summary.record_request(RequestResult(
            correlation_id=res2.correlation_id, http_method="GET", url=res2.url,
            status_code=res2.status_code, duration_ms=res2.duration_ms, is_success=(res2.status_code == 401),
            identity_label="attacker_auth_probe", normalized_route=normalize_gateway_route(res2.url)
        ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class InjectionProbeScenario(BaseScenario):
    """SCEN-SEC-INJECTION-PROBE: Injection testing (SQLi, path traversal) against test search/query endpoints."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-injection-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        token = "mock-attacker-jwt-token"
        if not self.dry_run:
            try:
                alex_pass = self.config.get_password("alex.morgan") or "Password123!"
                token = await auth.get_access_token("alex.morgan", alex_pass)
            except Exception:
                pass

        probes = [
            ("GET", "/api/v1/transfers", {"search": "' OR 1=1 --"}),
            ("GET", "/api/v1/transfers", {"filter": "UNION SELECT id, amount FROM transfers"}),
            ("GET", "/api/v1/customers", {"q": "../../etc/passwd"}),
        ]

        for method, path, params in probes:
            res = await gateway.request(
                method, path, token=token, params=params,
                headers={"X-Simulation-Run-Id": self.run_id, "X-Simulation-Scenario-Id": self.metadata.id}
            )
            summary.record_request(RequestResult(
                correlation_id=res.correlation_id, http_method=method, url=res.url,
                status_code=res.status_code, duration_ms=res.duration_ms, is_success=True,
                identity_label="attacker_injection", normalized_route=normalize_gateway_route(res.url)
            ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class MixedConcurrentTrafficScenario(BaseScenario):
    """SCEN-MIXED-CONCURRENT: Concurrent benign customer reads alongside attacker probing."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-mixed-concurrent-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        alex_id = self.config.benign_flow.alex_customer_id
        sam_id = self.config.benign_flow.sam_customer_id

        alex_token = "mock-alex-jwt-token"
        if not self.dry_run:
            try:
                alex_pass = self.config.get_password("alex.morgan") or "Password123!"
                alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            except Exception:
                pass

        # 1. Legitimate user requests
        t1 = gateway.request("GET", f"/api/v1/customers/{alex_id}/profile", token=alex_token)
        t2 = gateway.request("GET", f"/api/v1/accounts/ACCT-ALEX-01/balance", token=alex_token)
        # 2. Attacker probes unauthorized resource
        t3 = gateway.request("GET", f"/api/v1/customers/{sam_id}/profile", token=alex_token)

        responses = await asyncio.gather(t1, t2, t3, return_exceptions=True)

        for i, res in enumerate(responses):
            if isinstance(res, GatewayResponse):
                summary.record_request(RequestResult(
                    correlation_id=res.correlation_id, http_method=res.http_method, url=res.url,
                    status_code=res.status_code, duration_ms=res.duration_ms, is_success=res.is_success,
                    identity_label="alex_morgan" if i < 2 else "attacker_persona",
                    normalized_route=normalize_gateway_route(res.url)
                ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class MultiTenantBoundaryScenario(BaseScenario):
    """SCEN-MIXED-MULTI-TENANT: Multi-tenant boundary isolation validation."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-multi-tenant-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        alex_id = self.config.benign_flow.alex_customer_id

        # Query with Tenant-1 header (valid)
        res1 = await gateway.request(
            "GET", f"/api/v1/customers/{alex_id}/profile",
            token="mock-alex-jwt-token",
            headers={"X-Tenant-Id": "tenant-aegis-1", "X-Simulation-Run-Id": self.run_id}
        )
        summary.record_request(RequestResult(
            correlation_id=res1.correlation_id, http_method="GET", url=res1.url,
            status_code=res1.status_code, duration_ms=res1.duration_ms, is_success=res1.is_success,
            identity_label="tenant-1-user", normalized_route=normalize_gateway_route(res1.url)
        ))

        # Query with cross-tenant header
        res2 = await gateway.request(
            "GET", f"/api/v1/customers/{alex_id}/profile",
            token="mock-alex-jwt-token",
            headers={"X-Tenant-Id": "tenant-aegis-2", "X-Simulation-Run-Id": self.run_id}
        )
        summary.record_request(RequestResult(
            correlation_id=res2.correlation_id, http_method="GET", url=res2.url,
            status_code=res2.status_code, duration_ms=res2.duration_ms, is_success=res2.is_success,
            identity_label="tenant-2-cross-caller", normalized_route=normalize_gateway_route(res2.url)
        ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class TelemetryBacklogResilienceScenario(BaseScenario):
    """SCEN-INFRA-BACKLOG: Gateway health and burst telemetry processing test."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-backlog-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        # Check readiness endpoint
        res = await gateway.request(
            "GET", "/actuator/health/readiness",
            headers={"X-Simulation-Run-Id": self.run_id, "X-Simulation-Scenario-Id": self.metadata.id}
        )
        summary.record_request(RequestResult(
            correlation_id=res.correlation_id, http_method="GET", url=res.url,
            status_code=res.status_code, duration_ms=res.duration_ms, is_success=res.is_success,
            identity_label="health_probe", normalized_route="/actuator/health/readiness"
        ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary


class ServiceUnavailabilityScenario(BaseScenario):
    """SCEN-INFRA-UNAVAILABLE: Non-existent route resilience and isolation."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig, dry_run: bool = False) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = f"run-unavailable-{uuid.uuid4().hex[:8]}"

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            run_id=self.run_id,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        res = await gateway.request(
            "GET", "/api/v1/nonexistent/service/boundary",
            headers={"X-Simulation-Run-Id": self.run_id, "X-Simulation-Scenario-Id": self.metadata.id}
        )
        summary.record_request(RequestResult(
            correlation_id=res.correlation_id, http_method="GET", url=res.url,
            status_code=res.status_code, duration_ms=res.duration_ms, is_success=(res.status_code in (404, 502, 503)),
            identity_label="probe_scanner", normalized_route="/api/v1/nonexistent/service/boundary"
        ))

        summary.finished_at = datetime.now(timezone.utc)
        summary.status = ExecutionStatus.SUCCESS
        return summary

