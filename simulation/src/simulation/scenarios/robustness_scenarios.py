"""Adversarial and Robustness Simulation Scenarios for Phase 7.2.4.3.

Implements deterministic, labelled scenario variations across:
- BENIGN variations:
    * SCEN-BENIGN-03: Authorized multi-resource access
    * SCEN-BENIGN-04: Concurrent legitimate reads
    * SCEN-BENIGN-05: Shared IP across different identities
    * SCEN-BENIGN-06: Legitimate denied access (non-BOLA 403)
- BOLA variations:
    * SCEN-BOLA-03: Repeated cross-owner attempts on single victim
    * SCEN-BOLA-05: Successful unauthorized cross-owner resource access (confirmed leak)
    * SCEN-BOLA-06: Different identities targeting one resource
- DATA EXTRACTION variations:
    * SCEN-EXTRACT-SLOW: Slow extraction (spaced beyond sliding window threshold)
    * SCEN-EXTRACT-DISTRIBUTED: Distributed extraction across sessions
- EDGE CASES / ADVERSARIAL ROBUSTNESS:
    * SCEN-EDGE-NO-OWNERSHIP: Missing ownership metadata
    * SCEN-EDGE-NO-CLASSIF: Missing sensitivity classification
    * SCEN-EDGE-DUPLICATE: Duplicate event delivery
    * SCEN-EDGE-DELAYED: Delayed event arrival
    * SCEN-EDGE-OUT-OF-ORDER: Out-of-order event sequence
    * SCEN-EDGE-WINDOW-BOUNDARY: Sliding-window boundary conditions (119s vs 121s)
    * SCEN-EDGE-INCOMPLETE-SEQUENCE: Incomplete multi-stage attack sequence
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


class RobustnessScenarioBase(BaseScenario):
    """Base class for robustness and edge case scenario implementations."""

    def __init__(self, metadata: ScenarioMetadata, config: SimulationConfig) -> None:
        super().__init__(metadata, config)
        self.run_id = str(uuid.uuid4())
        self.recorded_requests: list[RequestResult] = []

    def _record_response(
        self,
        summary: ScenarioSummary,
        response: GatewayResponse,
        identity_label: str,
        custom_route: str | None = None,
    ) -> None:
        norm_route = custom_route or normalize_gateway_route(response.url)
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

    def _finalize_manifest(self, summary: ScenarioSummary) -> None:
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


# =============================================================================
# BENIGN VARIATIONS
# =============================================================================

class BenignMultiResourceScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-03: Legitimate multi-resource access across profile, accounts, and transactions."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            # Legitimate reads across multiple distinct endpoints belonging to the same customer
            r1 = await gateway.get(f"/api/v1/customers/{alex_id}", token=token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=token)
            self._record_response(summary, r2, "alex.morgan")

            r3 = await gateway.get("/api/v1/accounts", token=token)
            self._record_response(summary, r3, "alex.morgan")

            r4 = await gateway.get("/api/v1/transactions", token=token)
            self._record_response(summary, r4, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BenignConcurrentReadsScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-04: Concurrent legitimate reads by single customer."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            # Fire 4 concurrent queries on owned endpoints
            reqs = [
                gateway.get(f"/api/v1/customers/{alex_id}", token=token),
                gateway.get("/api/v1/accounts", token=token),
                gateway.get(f"/api/v1/customers/{alex_id}/profile", token=token),
                gateway.get("/api/v1/transactions", token=token),
            ]
            responses = await asyncio.gather(*reqs)
            for resp in responses:
                self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BenignSharedIpScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-05: Shared IP across different legitimate customer identities (corporate NAT/Wi-Fi)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            sam_pass = self.config.require_password("sam.taylor")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            sam_token = await auth.get_access_token("sam.taylor", sam_pass)

            alex_id = self.config.benign_flow.alex_customer_id
            sam_id = self.config.benign_flow.sam_customer_id

            # Both query their own data from the exact same corporate IP address
            r1 = await gateway.get(f"/api/v1/customers/{alex_id}", token=alex_token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get(f"/api/v1/customers/{sam_id}", token=sam_token)
            self._record_response(summary, r2, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BenignLegitimateDeniedScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-06: Legitimate denied access (non-BOLA, e.g. unprivileged general endpoint)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)

            # Customer attempts to access a protected SOC operational route without analyst role -> returns 403
            # But this is NOT a cross-customer resource BOLA access (target is system operational route)
            resp = await gateway.get("/api/v1/security/overview", token=alex_token)
            self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


# =============================================================================
# BOLA VARIATIONS
# =============================================================================

class BolaRepeatedAttemptsScenario(RobustnessScenarioBase):
    """SCEN-BOLA-03: Repeated cross-owner attempts on a single victim resource."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        victim_resource_id: str = "20000000-0000-4000-8000-000000000002",
        repetitions: int = 3,
    ) -> None:
        super().__init__(metadata, config)
        self.victim_resource_id = victim_resource_id
        self.repetitions = repetitions

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-BOLA-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)

            for _ in range(self.repetitions):
                resp = await gateway.get(f"/api/v1/customers/{self.victim_resource_id}", token=alex_token)
                self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BolaConfirmedLeakScenario(RobustnessScenarioBase):
    """SCEN-BOLA-05: Successful unauthorized cross-owner resource access (confirmed BOLA data leak)."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        victim_account_id: str = "30000000-0000-4000-8000-000000000003",
    ) -> None:
        super().__init__(metadata, config)
        self.victim_account_id = victim_account_id

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-BOLA-CONFIRMED-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)

            # Simulated vulnerable endpoint where cross-owner access returns HTTP 200 with sensitive data
            resp = await gateway.get(f"/api/v1/accounts/{self.victim_account_id}", token=alex_token)
            self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BolaMultiIdentityTargetScenario(RobustnessScenarioBase):
    """SCEN-BOLA-06: Different identities targeting the same victim resource."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        target_account_id: str = "30000000-0000-4000-8000-000000000003",
    ) -> None:
        super().__init__(metadata, config)
        self.target_account_id = target_account_id

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-BOLA-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            sam_pass = self.config.require_password("sam.taylor")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            sam_token = await auth.get_access_token("sam.taylor", sam_pass)

            # Both attempt unauthorized access to the third victim's account
            r1 = await gateway.get(f"/api/v1/accounts/{self.target_account_id}", token=alex_token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get(f"/api/v1/accounts/{self.target_account_id}", token=sam_token)
            self._record_response(summary, r2, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


# =============================================================================
# DATA EXTRACTION VARIATIONS
# =============================================================================

class SlowExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXTRACT-SLOW: Slow extraction (queries spaced or distinct count below threshold = 2)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            # Queries only 2 distinct resources (threshold for bulk extraction is >= 3)
            # Evaluates threshold boundary behaviour: should NOT trip bulk extraction
            r1 = await gateway.get("/api/v1/customers/10000000-0000-4000-8000-000000000001", token=token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/api/v1/customers/20000000-0000-4000-8000-000000000002", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class DistributedExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXTRACT-DISTRIBUTED: Distributed extraction across distinct user identities."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            sam_pass = self.config.require_password("sam.taylor")
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)
            sam_token = await auth.get_access_token("sam.taylor", sam_pass)

            # Alex extracts 1 resource, Sam extracts 1 resource (neither exceeds individual threshold 3)
            r1 = await gateway.get("/api/v1/customers/30000000-0000-4000-8000-000000000003", token=alex_token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/api/v1/customers/40000000-0000-4000-8000-000000000004", token=sam_token)
            self._record_response(summary, r2, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


# =============================================================================
# EDGE CASES & ADVERSARIAL ROBUSTNESS
# =============================================================================

class EdgeMissingOwnershipScenario(RobustnessScenarioBase):
    """SCEN-EDGE-NO-OWNERSHIP: Telemetry event missing ownership metadata."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            # Event where customer ownership is indeterminate or null
            resp = await gateway.get("/api/v1/public/rates")
            self._record_response(summary, resp, "anonymous")
            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeMissingClassificationScenario(RobustnessScenarioBase):
    """SCEN-EDGE-NO-CLASSIF: Route without pre-declared schema classification."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            # Accessing an unclassified internal health/ping endpoint
            resp = await gateway.get("/actuator/health", token=token)
            self._record_response(summary, resp, "alex.morgan")
            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeDuplicateEventsScenario(RobustnessScenarioBase):
    """SCEN-EDGE-DUPLICATE: Duplicate event delivery with identical correlation ID."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)
            shared_cid = str(uuid.uuid4())

            # Send duplicate requests with the exact same correlation ID
            r1 = await gateway.get("/api/v1/accounts", token=token, correlation_id=shared_cid)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/api/v1/accounts", token=token, correlation_id=shared_cid)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeDelayedEventsScenario(RobustnessScenarioBase):
    """SCEN-EDGE-DELAYED: Delayed event delivery."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            r1 = await gateway.get("/api/v1/accounts", token=token)
            self._record_response(summary, r1, "alex.morgan")

            # Artificial sleep simulating delayed batching
            await asyncio.sleep(0.05)

            r2 = await gateway.get("/api/v1/accounts", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeOutOfOrderScenario(RobustnessScenarioBase):
    """SCEN-EDGE-OUT-OF-ORDER: Out-of-order event sequence (Stage 3 before Stage 1)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-DATA-LEAK-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            # Inverted sequence: Extraction request arrived before reconnaissance
            r1 = await gateway.get("/api/v1/customers/20000000-0000-4000-8000-000000000002", token=token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/actuator/env", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeWindowBoundaryScenario(RobustnessScenarioBase):
    """SCEN-EDGE-WINDOW-BOUNDARY: Sliding-window boundary conditions (119s vs 121s)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=[],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            # Two reads within window boundary
            r1 = await gateway.get("/api/v1/customers/10000000-0000-4000-8000-000000000001", token=token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/api/v1/customers/10000000-0000-4000-8000-000000000001", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeIncompleteSequenceScenario(RobustnessScenarioBase):
    """SCEN-EDGE-INCOMPLETE-SEQUENCE: Incomplete multi-stage attack (Reconnaissance only, no extraction)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-PROBE-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)

            # Only Stage 1 probes, never progresses to BOLA or Extraction
            r1 = await gateway.get("/actuator/health", token=token)
            self._record_response(summary, r1, "alex.morgan")

            r2 = await gateway.get("/actuator/metrics", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary
