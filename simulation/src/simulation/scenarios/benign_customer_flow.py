"""End-to-End Benign FinTech Customer Journey (SCEN-BENIGN-01).

Implements a realistic, legitimate multi-customer banking journey:
- Alex Morgan checks profile, selects active account, manages/verifies beneficiary,
  and executes an authorized transfer with idempotency.
- Sam Taylor performs independent read-only profile and account inquiry using a distinct identity token.
- Fully instruments all requests with correlation IDs, latency measurement, and safeguards against
  unintentional data mutation (supporting preflight dry-run mode).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient, GatewayResponse
from simulation.config import SimulationConfig
from simulation.models import (
    ExecutionStatus,
    RequestResult,
    ScenarioMetadata,
    ScenarioSummary,
)
from simulation.scenarios.base import BaseScenario

log = logging.getLogger(__name__)


class BenignCustomerFlow(BaseScenario):
    """Executes the SCEN-BENIGN-01 end-to-end banking customer scenario."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
        dry_run: bool = False,
    ) -> None:
        super().__init__(metadata, config)
        self.dry_run = dry_run
        self.run_id = str(uuid.uuid4())
        self.created_resources: dict[str, str] = {}
        self.recorded_correlation_ids: list[str] = []

    def _record_response(
        self,
        summary: ScenarioSummary,
        response: GatewayResponse,
        identity_label: str,
    ) -> None:
        """Records a gateway response into the scenario execution summary."""
        self.recorded_correlation_ids.append(response.correlation_id)
        result = RequestResult(
            correlation_id=response.correlation_id,
            http_method=response.http_method,
            url=response.url,
            status_code=response.status_code,
            duration_ms=response.duration_ms,
            is_success=response.is_success,
            error_message=None if response.is_success else f"HTTP {response.status_code} ({identity_label})",
        )
        summary.record_request(result)

    async def execute(
        self,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
    ) -> ScenarioSummary:
        """Executes the full end-to-end banking journey."""
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        flow_cfg = self.config.benign_flow
        alex_id = flow_cfg.alex_customer_id
        sam_id = flow_cfg.sam_customer_id

        # ----------------------------------------------------------------------
        # Identity 1: Alex Morgan Authentication
        # ----------------------------------------------------------------------
        log.info("[%s] Authenticating as Alex Morgan...", self.metadata.id)
        alex_pass = self.config.get_password("alex.morgan")
        alex_token = await auth.get_access_token("alex.morgan", alex_pass)

        # ----------------------------------------------------------------------
        # Step A: Customer Profile
        # ----------------------------------------------------------------------
        log.info("[%s] Step A: Retrieving Alex's customer record and profile", self.metadata.id)
        resp_cust = await gateway.get(f"/api/v1/customers/{alex_id}", token=alex_token)
        self._record_response(summary, resp_cust, "alex.morgan")
        if not resp_cust.is_success:
            raise RuntimeError(f"Step A failed: Customer {alex_id} not found (HTTP {resp_cust.status_code})")

        resp_profile = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=alex_token)
        self._record_response(summary, resp_profile, "alex.morgan")
        if not resp_profile.is_success:
            raise RuntimeError(f"Step A failed: Profile for {alex_id} not found (HTTP {resp_profile.status_code})")

        # ----------------------------------------------------------------------
        # Step B: Account Access & Balance Inquiry
        # ----------------------------------------------------------------------
        log.info("[%s] Step B: Retrieving Alex's accounts and balance", self.metadata.id)
        resp_accounts = await gateway.get("/api/v1/accounts", token=alex_token)
        self._record_response(summary, resp_accounts, "alex.morgan")
        if not resp_accounts.is_success:
            raise RuntimeError(f"Step B failed: Could not list accounts (HTTP {resp_accounts.status_code})")

        accounts_data = resp_accounts.json()
        if not isinstance(accounts_data, list) or len(accounts_data) == 0:
            raise RuntimeError(f"Step B failed: No accounts returned for customer {alex_id}")

        # Find eligible active USD account with sufficient balance for transfer
        selected_account: dict[str, Any] | None = None
        for acct in accounts_data:
            if acct.get("status") == "ACTIVE" and acct.get("currency") == flow_cfg.transfer_currency:
                bal = float(acct.get("balance", 0.0))
                if bal >= flow_cfg.transfer_amount:
                    selected_account = acct
                    break

        if not selected_account:
            # Fallback to first active account
            selected_account = next((a for a in accounts_data if a.get("status") == "ACTIVE"), accounts_data[0])

        account_id = selected_account["id"]
        self.created_resources["selected_account_id"] = str(account_id)

        # Retrieve account details and balance
        resp_acct = await gateway.get(f"/api/v1/accounts/{account_id}", token=alex_token)
        self._record_response(summary, resp_acct, "alex.morgan")

        resp_bal = await gateway.get(f"/api/v1/accounts/{account_id}/balance", token=alex_token)
        self._record_response(summary, resp_bal, "alex.morgan")
        if resp_bal.is_success:
            initial_balance = resp_bal.json().get("availableBalance")
            log.info("[%s] Selected account %s balance: %s %s", self.metadata.id, account_id, initial_balance, flow_cfg.transfer_currency)

        # ----------------------------------------------------------------------
        # Step C: Beneficiary Workflow
        # ----------------------------------------------------------------------
        log.info("[%s] Step C: Managing beneficiary for Sam Taylor (%s)", self.metadata.id, flow_cfg.destination_account_reference)
        resp_bens = await gateway.get("/api/v1/beneficiaries", token=alex_token)
        self._record_response(summary, resp_bens, "alex.morgan")

        beneficiary_id: str | None = None
        if resp_bens.is_success and isinstance(resp_bens.json(), list):
            for b in resp_bens.json():
                if b.get("destinationAccountReference") == flow_cfg.destination_account_reference:
                    beneficiary_id = str(b.get("id"))
                    ben_status = b.get("status")
                    log.info("[%s] Found existing beneficiary %s (status: %s)", self.metadata.id, beneficiary_id, ben_status)
                    if ben_status != "VERIFIED":
                        # Verify existing beneficiary
                        resp_verify = await gateway.post(f"/api/v1/beneficiaries/{beneficiary_id}/verify", token=alex_token)
                        self._record_response(summary, resp_verify, "alex.morgan")
                    break

        if not beneficiary_id:
            if self.dry_run:
                beneficiary_id = "00000000-0000-0000-0000-000000000000"
                log.info("[%s] [DRY-RUN] Simulated beneficiary registration for Sam Taylor", self.metadata.id)
            else:
                create_payload = {
                    "customerId": alex_id,
                    "name": "Sam Taylor",
                    "destinationAccountReference": flow_cfg.destination_account_reference,
                    "currency": flow_cfg.transfer_currency,
                }
                resp_create = await gateway.post("/api/v1/beneficiaries", token=alex_token, json=create_payload)
                self._record_response(summary, resp_create, "alex.morgan")
                if not resp_create.is_success:
                    raise RuntimeError(f"Step C failed: Beneficiary creation failed (HTTP {resp_create.status_code})")

                beneficiary_id = str(resp_create.json()["id"])
                self.created_resources["beneficiary_id"] = beneficiary_id

                # Verify beneficiary
                resp_verify = await gateway.post(f"/api/v1/beneficiaries/{beneficiary_id}/verify", token=alex_token)
                self._record_response(summary, resp_verify, "alex.morgan")
                if not resp_verify.is_success:
                    raise RuntimeError(f"Step C failed: Beneficiary verification failed (HTTP {resp_verify.status_code})")

        self.created_resources["beneficiary_id"] = str(beneficiary_id)

        # ----------------------------------------------------------------------
        # Step D: Transfer Workflow
        # ----------------------------------------------------------------------
        if self.dry_run:
            log.info(
                "[%s] [DRY-RUN] Preflight validation complete. Transfer of %s %s to beneficiary %s skipped.",
                self.metadata.id, flow_cfg.transfer_amount, flow_cfg.transfer_currency, beneficiary_id,
            )
            self.created_resources["transfer_status"] = "SKIPPED_DRY_RUN"
        else:
            ref = f"BENIGN-TX-{uuid.uuid4().hex[:10].upper()}"
            idem_key = f"IDEM-{uuid.uuid4().hex[:16]}"
            transfer_body = {
                "customerId": alex_id,
                "sourceAccountId": str(account_id),
                "beneficiaryId": str(beneficiary_id),
                "amount": flow_cfg.transfer_amount,
                "currency": flow_cfg.transfer_currency,
                "reference": ref,
            }

            log.info(
                "[%s] Step D: Executing transfer of %s %s from %s to %s [Ref: %s]",
                self.metadata.id, flow_cfg.transfer_amount, flow_cfg.transfer_currency, account_id, beneficiary_id, ref,
            )

            resp_tx = await gateway.post(
                "/api/v1/transfers",
                token=alex_token,
                json=transfer_body,
                headers={"Idempotency-Key": idem_key},
            )
            self._record_response(summary, resp_tx, "alex.morgan")
            if not resp_tx.is_success:
                raise RuntimeError(f"Step D failed: Transfer failed (HTTP {resp_tx.status_code}): {resp_tx.text}")

            tx_data = resp_tx.json()
            tx_id = str(tx_data["id"])
            self.created_resources["transaction_id"] = tx_id
            self.created_resources["transaction_reference"] = ref
            self.created_resources["transaction_status"] = tx_data.get("status", "UNKNOWN")

            # Verify balance post-transfer
            resp_post_bal = await gateway.get(f"/api/v1/accounts/{account_id}/balance", token=alex_token)
            self._record_response(summary, resp_post_bal, "alex.morgan")

        # ----------------------------------------------------------------------
        # Step E: Transaction History
        # ----------------------------------------------------------------------
        log.info("[%s] Step E: Querying transaction history for Alex", self.metadata.id)
        resp_txs = await gateway.get("/api/v1/transactions", token=alex_token)
        self._record_response(summary, resp_txs, "alex.morgan")

        if not self.dry_run and "transaction_id" in self.created_resources:
            tx_id = self.created_resources["transaction_id"]
            resp_single_tx = await gateway.get(f"/api/v1/transactions/{tx_id}", token=alex_token)
            self._record_response(summary, resp_single_tx, "alex.morgan")

        # ----------------------------------------------------------------------
        # Step F: Sam's Independent Journey (Separate Identity)
        # ----------------------------------------------------------------------
        log.info("[%s] Step F: Authenticating as Sam Taylor and performing independent inquiry...", self.metadata.id)
        sam_pass = self.config.get_password("sam.taylor")
        sam_token = await auth.get_access_token("sam.taylor", sam_pass)

        # Sam checks own profile
        resp_sam_prof = await gateway.get(f"/api/v1/customers/{sam_id}/profile", token=sam_token)
        self._record_response(summary, resp_sam_prof, "sam.taylor")

        # Sam lists own accounts
        resp_sam_accts = await gateway.get("/api/v1/accounts", token=sam_token)
        self._record_response(summary, resp_sam_accts, "sam.taylor")

        if resp_sam_accts.is_success and isinstance(resp_sam_accts.json(), list) and len(resp_sam_accts.json()) > 0:
            sam_acct_id = resp_sam_accts.json()[0]["id"]
            resp_sam_bal = await gateway.get(f"/api/v1/accounts/{sam_acct_id}/balance", token=sam_token)
            self._record_response(summary, resp_sam_bal, "sam.taylor")

        log.info(
            "[%s] Completed benign customer journey: %d total requests, %d success, %d failed",
            self.metadata.id, summary.total_requests, summary.successful_requests, summary.failed_requests,
        )

        return summary

