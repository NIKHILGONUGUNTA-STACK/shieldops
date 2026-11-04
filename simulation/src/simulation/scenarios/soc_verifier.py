"""Aegis SOC Telemetry and Security Verification Engine.

Queries actual Aegis SOC APIs using an authorized analyst identity to independently
verify passive telemetry ingestion, incident correlation boundaries, API reconciliation,
and posture invariants following a simulation run.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any
from pydantic import BaseModel, Field

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig

log = logging.getLogger(__name__)


class SocVerificationResult(BaseModel):
    """Structured results from SOC verification queries."""

    run_id: str
    analyst_identity: str = "analyst"
    total_expected_events: int = 0
    events_verified: int = 0
    missing_correlation_ids: list[str] = Field(default_factory=list)
    new_incidents_count: int = 0
    new_incidents: list[dict[str, Any]] = Field(default_factory=list)
    reconciliation_summary: dict[str, Any] = Field(default_factory=dict)
    posture_confirmed_vulnerability_false: bool = True
    verification_passed: bool = True
    diagnostics: list[str] = Field(default_factory=list)


class SocTelemetryVerifier:
    """Verifies gateway wire telemetry and SOC invariants via authorized analyst APIs."""

    def __init__(
        self,
        config: SimulationConfig,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
    ) -> None:
        self.config = config
        self.gateway = gateway
        self.auth = auth

    async def verify_benign_run(
        self,
        correlation_ids: list[str],
        start_time: datetime,
        end_time: datetime,
        run_id: str,
    ) -> SocVerificationResult:
        """Executes bounded asynchronous polling and assertions across Aegis SOC endpoints."""
        result = SocVerificationResult(
            run_id=run_id,
            total_expected_events=len(correlation_ids),
        )

        log.info("[%s] Beginning SOC telemetry verification using analyst identity...", run_id)

        # 1. Acquire Analyst Token
        try:
            analyst_pass = self.config.get_password("analyst")
            analyst_token = await self.auth.get_access_token("analyst", analyst_pass)
        except Exception as e:
            result.verification_passed = False
            result.diagnostics.append(f"Failed to authenticate as analyst: {e}")
            log.error("[%s] Analyst authentication failed during SOC verification: %s", run_id, e)
            return result

        timeout = self.config.execution.soc_verification_timeout_seconds
        interval = self.config.execution.soc_verification_interval_seconds

        # 2. Bounded Polling for Telemetry Events by Correlation ID
        log.info(
            "[%s] Polling /api/v1/security/events for %d correlation IDs (timeout: %.1fs)...",
            run_id, len(correlation_ids), timeout,
        )

        for cid in correlation_ids:
            found = False
            start_poll = time.monotonic()

            while (time.monotonic() - start_poll) < timeout:
                try:
                    resp = await self.gateway.get(
                        "/api/v1/security/events",
                        token=analyst_token,
                        params={"correlationId": cid, "size": 5},
                    )
                    if resp.is_success:
                        data = resp.json()
                        total = data.get("totalElements", 0)
                        if total > 0:
                            found = True
                            result.events_verified += 1
                            break
                except Exception as e:
                    log.debug("Error probing events for CID %s: %s", cid, e)

                await asyncio.sleep(interval)

            if not found:
                result.missing_correlation_ids.append(cid)
                result.diagnostics.append(
                    f"Telemetry event for correlation ID {cid} was not ingested within {timeout}s timeout"
                )

        if result.missing_correlation_ids:
            result.verification_passed = False

        # 3. Verify No New Incidents Attributed to Benign Run
        log.info("[%s] Querying /api/v1/security/incidents to verify zero false positives...", run_id)
        try:
            from_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            to_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            resp_incidents = await self.gateway.get(
                "/api/v1/security/incidents",
                token=analyst_token,
                params={"from": from_str, "to": to_str, "size": 20},
            )
            if resp_incidents.is_success:
                inc_data = resp_incidents.json()
                items = inc_data.get("content", [])
                # Only flag incidents whose target entities match our benign simulation run
                target_customers = {
                    self.config.benign_flow.alex_customer_id,
                    self.config.benign_flow.sam_customer_id,
                }
                for inc in items:
                    target_val = inc.get("targetEntityValue", "")
                    if target_val in target_customers or any(cid in str(inc) for cid in correlation_ids):
                        result.new_incidents_count += 1
                        result.new_incidents.append(inc)

                if result.new_incidents_count > 0:
                    result.verification_passed = False
                    result.diagnostics.append(
                        f"Unexpected security incident(s) generated during benign run: "
                        f"{[i.get('ruleId') for i in result.new_incidents]}"
                    )
        except Exception as e:
            result.diagnostics.append(f"Failed to query security incidents: {e}")

        # 4. Query Reconciliation Summary
        log.info("[%s] Querying /api/v1/security/reconciliation summary...", run_id)
        try:
            resp_recon = await self.gateway.get(
                "/api/v1/security/reconciliation",
                token=analyst_token,
                params={"size": 10},
            )
            if resp_recon.is_success:
                recon_data = resp_recon.json()
                result.reconciliation_summary = recon_data.get("summary", {})
        except Exception as e:
            result.diagnostics.append(f"Failed to query reconciliation status: {e}")

        # 5. Query Security Posture Invariants
        log.info("[%s] Querying /api/v1/security/posture to verify safety invariants...", run_id)
        try:
            resp_posture = await self.gateway.get(
                "/api/v1/security/posture",
                token=analyst_token,
                params={"size": 20},
            )
            if resp_posture.is_success:
                posture_data = resp_posture.json()
                endpoints = posture_data.get("content", [])
                for ep in endpoints:
                    # Invariant: confirmedVulnerability must strictly remain false
                    if ep.get("confirmedVulnerability") is True:
                        result.posture_confirmed_vulnerability_false = False
                        result.verification_passed = False
                        result.diagnostics.append(
                            f"Safety Invariant Violation: Endpoint {ep.get('normalizedRoute')} has confirmedVulnerability=True"
                        )
        except Exception as e:
            result.diagnostics.append(f"Failed to query security posture: {e}")

        log.info(
            "[%s] SOC Verification completed: passed=%s (events: %d/%d, new incidents: %d)",
            run_id, result.verification_passed, result.events_verified,
            result.total_expected_events, result.new_incidents_count,
        )

        return result
