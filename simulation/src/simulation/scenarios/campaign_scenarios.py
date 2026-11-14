"""Multi-Stage Exfiltration Campaign Simulation Scenarios for Phase 7.2.4.5.

Implements realistic multi-stage kill-chain attack scenarios and benign lookalikes:
1. SCEN-EXFIL-RECON-PROBE: Reconnaissance followed by authorization probing.
2. SCEN-EXFIL-PROBE-EXTRACT: Authorization probing followed by extraction.
3. SCEN-EXFIL-EXPOSE-BULK: Sensitive-field exposure followed by bulk retrieval.
4. SCEN-EXFIL-LOW-SLOW-MULTI: Low-and-slow multi-domain extraction across Customer, Account, and Transfer.
5. SCEN-BENIGN-LOOKALIKE: Legitimate complex browsing activity resembling an attack sequence.
6. SCEN-MULTI-01: Multi-vector coordinated intrusion campaign.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any
import uuid

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import (
    ExecutionStatus,
    ScenarioMetadata,
    ScenarioSummary,
)
from simulation.scenarios.robustness_scenarios import RobustnessScenarioBase

log = logging.getLogger(__name__)


class ReconThenBolaProbingScenario(RobustnessScenarioBase):
    """SCEN-EXFIL-RECON-PROBE: Attacker probes system endpoints, then attempts BOLA on customer profiles."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-PROBE-01", "RULE-BOLA-01", "DATA_EXFILTRATION_CAMPAIGN"],
        )
        try:
            # Stage 1: Reconnaissance (404 on actuator)
            r1 = await gateway.get("/actuator/env")
            self._record_response(summary, r1, "unauthenticated")

            # Stage 2: Authorization Probing (403 on cross-owner profile)
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            r2 = await gateway.get(f"/api/v1/customers/{alex_id}", token=token)
            self._record_response(summary, r2, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class BolaProbingThenExtractionScenario(RobustnessScenarioBase):
    """SCEN-EXFIL-PROBE-EXTRACT: Probing followed by successful access to unauthorized resources."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-BOLA-01", "RULE-BOLA-CONFIRMED-01", "DATA_EXFILTRATION_CAMPAIGN"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            # Stage 2: Probe (403)
            r1 = await gateway.get(f"/api/v1/customers/{alex_id}", token=token)
            self._record_response(summary, r1, "sam.taylor")

            # Stage 4/5: Successful unauthorized access (200 on cross-owner victim account)
            r2 = await gateway.get("/api/v1/accounts/30000000-0000-4000-8000-000000000003", token=token)
            self._record_response(summary, r2, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class SensitiveExposureThenBulkScenario(RobustnessScenarioBase):
    """SCEN-EXFIL-EXPOSE-BULK: Sensitive-field exposure followed by bulk harvesting."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-EXCESSIVE-EXPOSURE-01", "RULE-ADV-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            sam_id = self.config.benign_flow.sam_customer_id

            # Stage 4: Access profile leaking undeclared fields
            r1 = await gateway.get(f"/api/v1/customers/{sam_id}/profile", token=token)
            self._record_response(summary, r1, "sam.taylor")

            # Stage 5: Rapid harvesting across pagination
            for p in range(3):
                r = await gateway.get(f"/api/v1/accounts?page={p}&size=10", token=token)
                self._record_response(summary, r, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class LowSlowMultiDomainScenario(RobustnessScenarioBase):
    """SCEN-EXFIL-LOW-SLOW-MULTI: Low-and-slow extraction spanning Customer, Account, and Beneficiaries."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-ADV-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"],
        )
        try:
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            sam_id = self.config.benign_flow.sam_customer_id

            # Cross-domain multi-resource queries
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


class BenignLookalikeScenario(RobustnessScenarioBase):
    """SCEN-BENIGN-LOOKALIKE: Benign activity resembling an attack (e.g. 404 on favicon, checking own profile)."""

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

            # Harmless 404 (e.g. missing asset)
            r1 = await gateway.get("/favicon.ico")
            self._record_response(summary, r1, "alex.morgan")

            # Normal own profile read
            r2 = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=token)
            self._record_response(summary, r2, "alex.morgan")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary


class MultiVectorCampaignScenario(RobustnessScenarioBase):
    """SCEN-MULTI-01: Full multi-vector intrusion campaign (Recon -> Credential Spray -> BOLA -> Exfil)."""

    async def execute(self, gateway: GatewayClient, auth: KeycloakAuthManager) -> ScenarioSummary:
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=["RULE-PROBE-01", "RULE-BOLA-01", "DATA_EXFILTRATION_CAMPAIGN"],
        )
        try:
            # 1. Recon
            r1 = await gateway.get("/actuator/mappings")
            self._record_response(summary, r1, "unauthenticated")

            # 2. BOLA probe
            sam_pass = self.config.require_password("sam.taylor")
            token = await auth.get_access_token("sam.taylor", sam_pass)
            alex_id = self.config.benign_flow.alex_customer_id

            r2 = await gateway.get(f"/api/v1/customers/{alex_id}", token=token)
            self._record_response(summary, r2, "sam.taylor")

            # 3. Extraction
            r3 = await gateway.get(f"/api/v1/customers/{self.config.benign_flow.sam_customer_id}/profile", token=token)
            self._record_response(summary, r3, "sam.taylor")

            summary.status = ExecutionStatus.SUCCESS
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
        finally:
            self._finalize_manifest(summary)
        return summary

