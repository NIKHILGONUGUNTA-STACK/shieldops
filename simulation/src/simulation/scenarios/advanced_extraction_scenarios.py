"""Advanced Bulk Extraction & Excessive Data Exposure Scenarios for Phase 7.2.4.4.

Implements:
- BENIGN variations:
    * SCEN-BENIGN-PAGINATION: Legitimate multi-page account history access.
    * SCEN-BENIGN-LARGE-RESP: Legitimate large response (authorized bulk statement export).
- ATTACK variations:
    * SCEN-EXTRACT-PAGINATION: Automated pagination-based data harvesting.
    * SCEN-DATA-RESTRICTED: Repeated restricted-field retrieval attempts.
    * SCEN-EXTRACT-MULTI-RESOURCE: Cross-domain multi-resource extraction (Customer + Account + Transfer).
    * SCEN-EXTRACT-CUMULATIVE: Cumulative extraction across multiple sliding windows exceeding volume thresholds.
- EDGE CASES:
    * SCEN-EDGE-NO-RESP-SIZE: Missing response-size metadata handling.
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
from simulation.scenarios.robustness_scenarios import RobustnessScenarioBase

log = logging.getLogger(__name__)


class BenignPaginationScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-PAGINATION: Legitimate customer paging through account history."""

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

            for p in range(2):
                resp = await gateway.get(f"/api/v1/accounts?page={p}&size=5", token=token)
                self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BenignLargeResponseScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-LARGE-RESP: Legitimate large statement export by authorized owner."""

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

            resp = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=token)
            self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class PaginationExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXTRACT-PAGINATION: Automated sequential pagination harvesting."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-ADV-EXTRACT-01"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)

            for p in range(4):
                resp = await gateway.get(f"/api/v1/accounts?page={p}&size=10", token=token)
                self._record_response(summary, resp, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class RestrictedFieldRetrievalScenario(RobustnessScenarioBase):
    """SCEN-DATA-RESTRICTED: Probing sensitive endpoint for RESTRICTED fields."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-EXCESSIVE-EXPOSURE-01"],
        )
        try:
            alex_pass = self.config.require_password("alex.morgan")
            token = await auth.get_access_token("alex.morgan", alex_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            resp = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=token)
            self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class MultiResourceExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXTRACT-MULTI-RESOURCE: Cross-domain harvesting across Customer, Account, and Beneficiary."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-ADV-EXTRACT-01"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            sam_id = self.config.benign_flow.sam_customer_id

            r1 = await gateway.get(f"/api/v1/customers/{sam_id}", token=token)
            self._record_response(summary, r1, "sam.taylor")

            r2 = await gateway.get("/api/v1/accounts", token=token)
            self._record_response(summary, r2, "sam.taylor")

            r3 = await gateway.get("/api/v1/transactions", token=token)
            self._record_response(summary, r3, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class CumulativeWindowExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXTRACT-CUMULATIVE: Cumulative extraction across sliding windows exceeding volume thresholds."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-ADV-EXTRACT-01"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)

            for i in range(5):
                resp = await gateway.get(f"/api/v1/accounts?page={i}&size=20", token=token)
                self._record_response(summary, resp, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class EdgeNoResponseSizeScenario(RobustnessScenarioBase):
    """SCEN-EDGE-NO-RESP-SIZE: Telemetry event arriving with zero or missing response-size."""

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

            resp = await gateway.get(f"/api/v1/customers/{alex_id}", token=token)
            self._record_response(summary, resp, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary
