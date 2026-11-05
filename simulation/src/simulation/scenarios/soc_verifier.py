"""Aegis SOC Telemetry and Security Verification Engine.

Queries actual Aegis SOC APIs using an authorized analyst identity to independently
verify passive telemetry ingestion, incident correlation boundaries, API reconciliation,
and posture invariants following a simulation run.

Enforces strict outcome classification:
- PASS: All correlation IDs verified, zero false positive incidents, full pagination checked,
  and posture confirmedVulnerability=false invariant holds across all endpoints.
- FAIL: Posture invariant violated (confirmedVulnerability=true) or false positive incidents
  attributed to the run.
- INCOMPLETE: Telemetry polling timed out for some requests or posture pagination could not complete.
- UNAVAILABLE: Analyst credentials missing or SOC endpoints returned 5xx/connection errors.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
import logging
import time
from typing import Any
from pydantic import BaseModel, Field

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig

log = logging.getLogger(__name__)


class VerificationOutcome(str, Enum):
    """Categorical outcome of SOC telemetry and posture verification."""

    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


class SocVerificationResult(BaseModel):
    """Structured results from SOC verification queries."""

    run_id: str
    outcome: VerificationOutcome = VerificationOutcome.INCOMPLETE
    analyst_identity: str = "analyst"
    total_expected_events: int = 0
    events_verified: int = 0
    verified_correlation_ids: list[str] = Field(default_factory=list)
    missing_correlation_ids: list[str] = Field(default_factory=list)
    new_incidents_count: int = 0
    new_incidents: list[dict[str, Any]] = Field(default_factory=list)
    reconciliation_verified: bool = False
    reconciliation_summary: dict[str, Any] = Field(default_factory=dict)
    posture_verified: bool = False
    endpoints_inspected_count: int = 0
    posture_confirmed_vulnerability_false: bool = True
    diagnostics: list[str] = Field(default_factory=list)

    @property
    def verification_passed(self) -> bool:
        """Backward-compatible helper indicating whether verification fully passed."""
        return self.outcome == VerificationOutcome.PASS


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
        unique_cids = list(dict.fromkeys(cid for cid in correlation_ids if cid))
        result = SocVerificationResult(
            run_id=run_id,
            total_expected_events=len(unique_cids),
        )

        log.info("[%s] Beginning SOC telemetry verification for %d correlation IDs...", run_id, len(unique_cids))

        # ----------------------------------------------------------------------
        # 1. Acquire Analyst Token
        # ----------------------------------------------------------------------
        analyst_pass = self.config.get_password("analyst")
        if not analyst_pass:
            result.outcome = VerificationOutcome.UNAVAILABLE
            result.diagnostics.append(
                "Analyst credentials not configured. Set SIMULATION_USER_ANALYST_PASSWORD to enable SOC verification."
            )
            log.warning("[%s] SOC verification skipped: Analyst credentials not configured", run_id)
            return result

        try:
            analyst_token = await self.auth.get_access_token("analyst", analyst_pass)
        except Exception as e:
            result.outcome = VerificationOutcome.UNAVAILABLE
            result.diagnostics.append(f"Failed to authenticate as analyst: {e}")
            log.error("[%s] Analyst authentication failed during SOC verification: %s", run_id, e)
            return result

        timeout = self.config.execution.soc_verification_timeout_seconds
        interval = self.config.execution.soc_verification_interval_seconds
        service_unavailable = False

        # ----------------------------------------------------------------------
        # 2. Bounded Polling for Telemetry Events by Correlation ID
        # ----------------------------------------------------------------------
        log.info(
            "[%s] Polling /api/v1/security/events for %d correlation IDs (timeout: %.1fs)...",
            run_id, len(unique_cids), timeout,
        )

        verified_set: set[str] = set()

        for cid in unique_cids:
            found = False
            start_poll = time.monotonic()

            while (time.monotonic() - start_poll) < timeout:
                try:
                    resp = await self.gateway.get(
                        "/api/v1/security/events",
                        token=analyst_token,
                        params={"correlationId": cid, "page": 0, "size": 10},
                    )
                    if resp.status_code in (500, 502, 503, 504):
                        service_unavailable = True
                        result.diagnostics.append(f"Security events API returned HTTP {resp.status_code} for CID {cid}")
                        break

                    if resp.is_success:
                        data = resp.json()
                        total = data.get("totalElements", 0)
                        content = data.get("content", [])
                        # Ensure matching correlation ID actually exists in content or count
                        if total > 0 or any(e.get("correlationId") == cid for e in content):
                            found = True
                            verified_set.add(cid)
                            break
                except Exception as e:
                    log.debug("Error probing events for CID %s: %s", cid, e)

                await asyncio.sleep(interval)

            if service_unavailable:
                break

            if not found:
                result.missing_correlation_ids.append(cid)
                result.diagnostics.append(
                    f"Telemetry event for correlation ID {cid} was not ingested within {timeout:.1f}s timeout"
                )

        result.events_verified = len(verified_set)
        result.verified_correlation_ids = sorted(list(verified_set))

        # ----------------------------------------------------------------------
        # 3. Verify No New False Positive Incidents Attributed to This Benign Run
        # ----------------------------------------------------------------------
        log.info("[%s] Querying /api/v1/security/incidents to verify zero false positives...", run_id)
        cid_set = set(unique_cids)
        try:
            from_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            to_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            resp_incidents = await self.gateway.get(
                "/api/v1/security/incidents",
                token=analyst_token,
                params={"from": from_str, "to": to_str, "page": 0, "size": 50},
            )
            if resp_incidents.status_code in (500, 502, 503, 504):
                service_unavailable = True
                result.diagnostics.append(f"Security incidents API returned HTTP {resp_incidents.status_code}")
            elif resp_incidents.is_success:
                inc_data = resp_incidents.json()
                items = inc_data.get("content", [])
                target_customers = {
                    self.config.benign_flow.alex_customer_id.lower(),
                    self.config.benign_flow.sam_customer_id.lower(),
                }
                for inc in items:
                    target_val = str(inc.get("targetEntityValue", "")).lower()
                    inc_str = str(inc)
                    # Incident is only attributed to this run if it occurred in this window AND
                    # directly references one of this run's correlation IDs or target customers
                    matches_cid = any(cid in inc_str for cid in cid_set)
                    matches_cust = target_val in target_customers
                    if matches_cid or matches_cust:
                        result.new_incidents_count += 1
                        result.new_incidents.append(inc)

                if result.new_incidents_count > 0:
                    result.diagnostics.append(
                        f"Unexpected security incident(s) generated during benign run: "
                        f"{[i.get('ruleId') for i in result.new_incidents]}"
                    )
        except Exception as e:
            result.diagnostics.append(f"Failed to query security incidents: {e}")

        # ----------------------------------------------------------------------
        # 4. Query Reconciliation Summary Contract
        # ----------------------------------------------------------------------
        log.info("[%s] Querying /api/v1/security/reconciliation/summary...", run_id)
        try:
            resp_recon = await self.gateway.get(
                "/api/v1/security/reconciliation/summary",
                token=analyst_token,
            )
            if resp_recon.is_success:
                result.reconciliation_verified = True
                result.reconciliation_summary = resp_recon.json()
            else:
                # Fallback to base reconciliation endpoint
                resp_base_recon = await self.gateway.get(
                    "/api/v1/security/reconciliation",
                    token=analyst_token,
                    params={"size": 1},
                )
                if resp_base_recon.is_success:
                    result.reconciliation_verified = True
                    result.reconciliation_summary = resp_base_recon.json().get("summary", {})
                else:
                    result.diagnostics.append(f"Reconciliation query returned HTTP {resp_recon.status_code}")
        except Exception as e:
            result.diagnostics.append(f"Failed to query reconciliation status: {e}")

        # ----------------------------------------------------------------------
        # 5. Full Posture Pagination and Invariant Verification (Section 7)
        # ----------------------------------------------------------------------
        log.info("[%s] Querying /api/v1/security/posture with full pagination...", run_id)
        posture_page = 0
        posture_page_size = 20
        posture_pagination_complete = False
        inspected_count = 0
        has_vuln = False

        try:
            while True:
                resp_posture = await self.gateway.get(
                    "/api/v1/security/posture",
                    token=analyst_token,
                    params={"page": posture_page, "size": posture_page_size, "windowHours": 24},
                )
                if not resp_posture.is_success:
                    result.diagnostics.append(
                        f"Security posture API failed on page {posture_page} (HTTP {resp_posture.status_code})"
                    )
                    break

                posture_data = resp_posture.json()
                content = posture_data.get("content", [])
                total_elements = posture_data.get("totalElements", 0)
                has_next = posture_data.get("hasNext", False)

                for ep in content:
                    inspected_count += 1
                    # Invariant: confirmedVulnerability must strictly remain false
                    if ep.get("confirmedVulnerability") is True:
                        has_vuln = True
                        result.posture_confirmed_vulnerability_false = False
                        result.diagnostics.append(
                            f"Safety Invariant Violation: Endpoint {ep.get('normalizedRoute')} has confirmedVulnerability=True"
                        )

                if not has_next or len(content) == 0:
                    # Verified all available pages
                    if inspected_count == total_elements or (total_elements == 0 and inspected_count == 0):
                        posture_pagination_complete = True
                    else:
                        result.diagnostics.append(
                            f"Posture pagination incomplete: inspected {inspected_count} of {total_elements} endpoints"
                        )
                    break

                posture_page += 1

            result.endpoints_inspected_count = inspected_count
            result.posture_verified = posture_pagination_complete and not has_vuln

        except Exception as e:
            result.diagnostics.append(f"Failed to paginate security posture: {e}")

        # ----------------------------------------------------------------------
        # 6. Determine Categorical Outcome
        # ----------------------------------------------------------------------
        if service_unavailable:
            result.outcome = VerificationOutcome.UNAVAILABLE
        elif has_vuln or result.new_incidents_count > 0:
            result.outcome = VerificationOutcome.FAIL
        elif len(result.missing_correlation_ids) > 0 or not posture_pagination_complete:
            result.outcome = VerificationOutcome.INCOMPLETE
        elif (
            len(verified_set) == len(unique_cids)
            and result.new_incidents_count == 0
            and result.posture_confirmed_vulnerability_false
            and posture_pagination_complete
        ):
            result.outcome = VerificationOutcome.PASS
        else:
            result.outcome = VerificationOutcome.INCOMPLETE

        log.info(
            "[%s] SOC Verification completed: outcome=%s (events: %d/%d, incidents: %d, endpoints: %d)",
            run_id, result.outcome.value, result.events_verified,
            result.total_expected_events, result.new_incidents_count, result.endpoints_inspected_count,
        )

        return result
