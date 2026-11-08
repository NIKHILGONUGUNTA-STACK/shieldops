"""End-to-End Benign FinTech Customer Journey (SCEN-BENIGN-01).

Implements a realistic, legitimate multi-customer banking journey:
- Alex Morgan checks profile, selects active account, manages/verifies beneficiary,
  and executes an authorized transfer with idempotency.
- Sam Taylor performs independent read-only profile and account inquiry using a distinct identity token.
- Fully instruments all requests with correlation IDs, latency measurement, and safeguards against
  unintentional data mutation (supporting preflight dry-run mode).
- Enforces strict account selection invariants, financial validation using Decimal arithmetic,
  genuinely non-mutating dry-run guarantees, and traceable run manifests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import logging
from typing import Any
import uuid

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import (
    GatewayClient,
    GatewayConnectionError,
    GatewayResponse,
    GatewayTimeoutError,
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
        self.planned_mutations: list[dict[str, Any]] = []
        self.recorded_correlation_ids: list[str] = []
        self.recorded_requests: list[RequestResult] = []

    def _record_response(
        self,
        summary: ScenarioSummary,
        response: GatewayResponse,
        identity_label: str,
    ) -> None:
        """Records a gateway response into the scenario execution summary and run trace."""
        self.recorded_correlation_ids.append(response.correlation_id)
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

    def _compile_manifest(self, summary: ScenarioSummary) -> RunManifest:
        """Constructs an independently traceable, sanitized run manifest."""
        return RunManifest(
            run_id=self.run_id,
            scenario_id=self.metadata.id,
            dry_run=self.dry_run,
            started_at=summary.started_at,
            finished_at=summary.finished_at,
            execution_outcome=summary.status.value,
            identities_used=["alex.morgan", "sam.taylor"],
            created_resources=dict(self.created_resources),
            planned_mutations=list(self.planned_mutations),
            total_requests=summary.total_requests,
            successful_requests=summary.successful_requests,
            failed_requests=summary.failed_requests,
            status_distribution=dict(summary.status_distribution),
            requests=list(self.recorded_requests),
        )

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
            run_id=self.run_id,
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        flow_cfg = self.config.benign_flow
        alex_id = flow_cfg.alex_customer_id
        sam_id = flow_cfg.sam_customer_id
        transfer_amt = Decimal(str(flow_cfg.transfer_amount))

        try:
            # ------------------------------------------------------------------
            # Preflight Step 0: Credential Availability & Identity Check
            # ------------------------------------------------------------------
            # Fail fast before any gateway/business requests if credentials are missing.
            alex_pass = self.config.require_password("alex.morgan")
            sam_pass = self.config.require_password("sam.taylor")

            # ------------------------------------------------------------------
            # Identity 1: Alex Morgan Authentication
            # ------------------------------------------------------------------
            log.info("[%s] Authenticating as Alex Morgan...", self.metadata.id)
            alex_token = await auth.get_access_token("alex.morgan", alex_pass)

            # ------------------------------------------------------------------
            # Step A: Customer Profile Retrieval & Verification
            # ------------------------------------------------------------------
            log.info("[%s] Step A: Retrieving Alex's customer record and profile", self.metadata.id)
            resp_cust = await gateway.get(f"/api/v1/customers/{alex_id}", token=alex_token)
            self._record_response(summary, resp_cust, "alex.morgan")
            if not resp_cust.is_success:
                raise RuntimeError(f"Step A failed: Customer {alex_id} lookup failed (HTTP {resp_cust.status_code})")

            resp_profile = await gateway.get(f"/api/v1/customers/{alex_id}/profile", token=alex_token)
            self._record_response(summary, resp_profile, "alex.morgan")
            if not resp_profile.is_success:
                raise RuntimeError(f"Step A failed: Profile for customer {alex_id} failed (HTTP {resp_profile.status_code})")

            # ------------------------------------------------------------------
            # Step B: Source Account Selection & Preflight Validation
            # ------------------------------------------------------------------
            log.info("[%s] Step B: Retrieving and strictly validating Alex's accounts and balance", self.metadata.id)
            resp_accounts = await gateway.get("/api/v1/accounts", token=alex_token)
            self._record_response(summary, resp_accounts, "alex.morgan")
            if not resp_accounts.is_success:
                raise RuntimeError(f"Step B failed: Could not list accounts (HTTP {resp_accounts.status_code})")

            accounts_data = resp_accounts.json()
            if not isinstance(accounts_data, list) or len(accounts_data) == 0:
                raise RuntimeError(f"Step B failed: No accounts returned for customer {alex_id}")

            # Enforce strict account selection conditions:
            # 1. Belongs to Alex Morgan (customerId == alex_id)
            # 2. Status == "ACTIVE"
            # 3. Currency == flow_cfg.transfer_currency
            # 4. Balance >= transfer_amount (using Decimal arithmetic)
            eligible_accounts: list[dict[str, Any]] = []
            for acct in accounts_data:
                acct_customer = str(acct.get("customerId", "")).lower()
                acct_status = acct.get("status")
                acct_currency = acct.get("currency")
                raw_bal = acct.get("balance")
                try:
                    acct_bal = Decimal(str(raw_bal)) if raw_bal is not None else Decimal(0)
                except Exception:
                    acct_bal = Decimal(0)

                if (
                    acct_customer == alex_id.lower()
                    and acct_status == "ACTIVE"
                    and acct_currency == flow_cfg.transfer_currency
                    and acct_bal >= transfer_amt
                ):
                    eligible_accounts.append(acct)

            # Strict Invariant: No fallback to arbitrary or insufficient accounts!
            if not eligible_accounts:
                raise RuntimeError(
                    f"Step B failed: No eligible source account found for Alex Morgan ({alex_id}). "
                    f"Required: status=ACTIVE, currency={flow_cfg.transfer_currency}, "
                    f"balance >= {transfer_amt}. Available accounts: {len(accounts_data)}"
                )

            selected_account = eligible_accounts[0]
            account_id = str(selected_account["id"])
            self.created_resources["selected_account_id"] = account_id

            # Validate account detail response schema
            resp_acct = await gateway.get(f"/api/v1/accounts/{account_id}", token=alex_token)
            self._record_response(summary, resp_acct, "alex.morgan")
            if not resp_acct.is_success:
                raise RuntimeError(f"Step B failed: Could not retrieve account details {account_id} (HTTP {resp_acct.status_code})")

            acct_detail = resp_acct.json()
            if str(acct_detail.get("customerId", "")).lower() != alex_id.lower():
                raise RuntimeError(f"Step B failed: Account {account_id} does not belong to customer {alex_id}")
            if acct_detail.get("status") != "ACTIVE":
                raise RuntimeError(f"Step B failed: Account {account_id} is not ACTIVE")
            if acct_detail.get("currency") != flow_cfg.transfer_currency:
                raise RuntimeError(f"Step B failed: Account {account_id} currency mismatch")

            # Validate account balance response schema (Balance record: availableBalance)
            resp_bal = await gateway.get(f"/api/v1/accounts/{account_id}/balance", token=alex_token)
            self._record_response(summary, resp_bal, "alex.morgan")
            if not resp_bal.is_success:
                raise RuntimeError(f"Step B failed: Could not retrieve balance for {account_id} (HTTP {resp_bal.status_code})")

            bal_data = resp_bal.json()
            if str(bal_data.get("accountId", "")).lower() != account_id.lower():
                raise RuntimeError(f"Step B failed: Balance response accountId mismatch")
            if bal_data.get("status") != "ACTIVE":
                raise RuntimeError(f"Step B failed: Balance response status is not ACTIVE")
            if bal_data.get("currency") != flow_cfg.transfer_currency:
                raise RuntimeError(f"Step B failed: Balance response currency mismatch")

            raw_avail = bal_data.get("availableBalance")
            if raw_avail is None:
                raise RuntimeError(f"Step B failed: Balance response missing 'availableBalance'")
            initial_balance = Decimal(str(raw_avail))
            if initial_balance < transfer_amt:
                raise RuntimeError(
                    f"Step B failed: Insufficient available balance. Required: {transfer_amt}, Available: {initial_balance}"
                )

            log.info(
                "[%s] Verified source account %s with available balance: %s %s",
                self.metadata.id, account_id, initial_balance, flow_cfg.transfer_currency,
            )
            self.created_resources["preflight_source_balance"] = str(initial_balance)

            # ------------------------------------------------------------------
            # Step C: Beneficiary Workflow
            # ------------------------------------------------------------------
            log.info(
                "[%s] Step C: Checking beneficiary for destination reference %s",
                self.metadata.id, flow_cfg.destination_account_reference,
            )
            resp_bens = await gateway.get("/api/v1/beneficiaries", token=alex_token)
            self._record_response(summary, resp_bens, "alex.morgan")
            if not resp_bens.is_success:
                raise RuntimeError(f"Step C failed: Could not retrieve beneficiaries (HTTP {resp_bens.status_code})")

            bens_list = resp_bens.json()
            if not isinstance(bens_list, list):
                raise RuntimeError("Step C failed: Beneficiary list response was not a JSON array")

            beneficiary_id: str | None = None
            for b in bens_list:
                if b.get("destinationAccountReference") == flow_cfg.destination_account_reference:
                    beneficiary_id = str(b.get("id"))
                    ben_status = b.get("status")
                    log.info("[%s] Found existing beneficiary %s (status: %s)", self.metadata.id, beneficiary_id, ben_status)

                    if ben_status != "VERIFIED":
                        if self.dry_run:
                            self.planned_mutations.append({
                                "action": "VERIFY_BENEFICIARY",
                                "beneficiaryId": beneficiary_id,
                                "destinationAccountReference": flow_cfg.destination_account_reference,
                            })
                            log.info("[%s] [DRY-RUN] Planned mutation: verify existing beneficiary %s", self.metadata.id, beneficiary_id)
                        else:
                            resp_verify = await gateway.post(f"/api/v1/beneficiaries/{beneficiary_id}/verify", token=alex_token)
                            self._record_response(summary, resp_verify, "alex.morgan")
                            if not resp_verify.is_success:
                                raise RuntimeError(f"Step C failed: Beneficiary verification failed (HTTP {resp_verify.status_code})")
                            verify_data = resp_verify.json()
                            if verify_data.get("status") != "VERIFIED":
                                raise RuntimeError(
                                    f"Step C failed: Beneficiary verification returned unexpected status '{verify_data.get('status')}'"
                                )
                    break

            if not beneficiary_id:
                if self.dry_run:
                    # Genuinely non-mutating: Do NOT generate fake IDs or call create API!
                    self.planned_mutations.append({
                        "action": "CREATE_BENEFICIARY",
                        "customerId": alex_id,
                        "name": "Sam Taylor",
                        "destinationAccountReference": flow_cfg.destination_account_reference,
                        "currency": flow_cfg.transfer_currency,
                    })
                    self.planned_mutations.append({
                        "action": "VERIFY_BENEFICIARY",
                        "destinationAccountReference": flow_cfg.destination_account_reference,
                    })
                    log.info(
                        "[%s] [DRY-RUN] Beneficiary does not exist. Recorded planned CREATE and VERIFY mutations.",
                        self.metadata.id,
                    )
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

                    create_data = resp_create.json()
                    beneficiary_id = str(create_data["id"])
                    self.created_resources["beneficiary_id"] = beneficiary_id

                    # Verify newly created beneficiary
                    resp_verify = await gateway.post(f"/api/v1/beneficiaries/{beneficiary_id}/verify", token=alex_token)
                    self._record_response(summary, resp_verify, "alex.morgan")
                    if not resp_verify.is_success:
                        raise RuntimeError(f"Step C failed: Beneficiary verification failed (HTTP {resp_verify.status_code})")

                    verify_data = resp_verify.json()
                    if verify_data.get("status") != "VERIFIED":
                        raise RuntimeError(
                            f"Step C failed: Beneficiary verification returned non-VERIFIED status: {verify_data.get('status')}"
                        )

            if beneficiary_id:
                self.created_resources["beneficiary_id"] = beneficiary_id

            # ------------------------------------------------------------------
            # Step D: Transfer Workflow & Dry-Run Non-Mutation Invariant
            # ------------------------------------------------------------------
            if self.dry_run:
                # Genuinely non-mutating dry run:
                # - No POST /transfers
                # - No fake transaction IDs
                # - Plan explicit mutation with projected balances
                projected_balance = initial_balance - transfer_amt
                self.planned_mutations.append({
                    "action": "EXECUTE_TRANSFER",
                    "customerId": alex_id,
                    "sourceAccountId": account_id,
                    "beneficiaryReference": flow_cfg.destination_account_reference,
                    "amount": str(transfer_amt),
                    "currency": flow_cfg.transfer_currency,
                    "preflightSourceBalance": str(initial_balance),
                    "projectedPostBalance": str(projected_balance),
                })
                self.created_resources["transfer_status"] = "SKIPPED_DRY_RUN"
                log.info(
                    "[%s] [DRY-RUN] Preflight verified. Planned transfer of %s %s to %s (projected balance: %s %s)",
                    self.metadata.id, transfer_amt, flow_cfg.transfer_currency,
                    flow_cfg.destination_account_reference, projected_balance, flow_cfg.transfer_currency,
                )
            else:
                if not beneficiary_id:
                    raise RuntimeError("Step D failed: Valid verified beneficiary ID is required for live transfer execution")

                ref = f"BENIGN-TX-{uuid.uuid4().hex[:12].upper()}"
                idem_key = str(uuid.uuid4())
                self.created_resources["idempotency_key"] = idem_key
                self.created_resources["transaction_reference"] = ref

                transfer_body = {
                    "customerId": alex_id,
                    "sourceAccountId": account_id,
                    "beneficiaryId": beneficiary_id,
                    "amount": float(transfer_amt),
                    "currency": flow_cfg.transfer_currency,
                    "reference": ref,
                }

                log.info(
                    "[%s] Step D: Executing transfer of %s %s from %s to %s [Ref: %s, IdemKey: %s]",
                    self.metadata.id, transfer_amt, flow_cfg.transfer_currency, account_id, beneficiary_id, ref, idem_key,
                )

                tx_data: dict[str, Any] | None = None
                try:
                    resp_tx = await gateway.post(
                        "/api/v1/transfers",
                        token=alex_token,
                        json=transfer_body,
                        headers={"Idempotency-Key": idem_key},
                    )
                    self._record_response(summary, resp_tx, "alex.morgan")

                    if resp_tx.is_success:
                        tx_data = resp_tx.json()
                    elif resp_tx.status_code in (502, 503, 504):
                        # Uncertain network/gateway response: initiate safe reconciliation instead of blind retry
                        log.warning(
                            "[%s] Uncertain transfer response (HTTP %d). Reconciling against transactions...",
                            self.metadata.id, resp_tx.status_code,
                        )
                        resp_tx_recon = await gateway.get("/api/v1/transactions", token=alex_token)
                        self._record_response(summary, resp_tx_recon, "alex.morgan")
                        if resp_tx_recon.is_success:
                            matching_tx = next((t for t in resp_tx_recon.json() if t.get("reference") == ref), None)
                            if matching_tx and matching_tx.get("status") == "COMPLETED":
                                log.info("[%s] Safe reconciliation confirmed completed transfer %s", self.metadata.id, matching_tx.get("id"))
                                tx_data = matching_tx
                            elif matching_tx and matching_tx.get("status") in ("PENDING", "AUTHORIZED"):
                                # Re-submit with the exact same Idempotency-Key
                                log.info("[%s] Safe reconciliation: Retrying with identical Idempotency-Key %s", self.metadata.id, idem_key)
                                resp_retry = await gateway.post(
                                    "/api/v1/transfers",
                                    token=alex_token,
                                    json=transfer_body,
                                    headers={"Idempotency-Key": idem_key},
                                )
                                self._record_response(summary, resp_retry, "alex.morgan")
                                if resp_retry.is_success:
                                    tx_data = resp_retry.json()
                        if not tx_data:
                            raise RuntimeError(
                                f"Step D failed: Transfer outcome uncertain (HTTP {resp_tx.status_code}) "
                                f"and safe reconciliation could not confirm completion for reference {ref}"
                            )
                    else:
                        raise RuntimeError(f"Step D failed: Transfer failed (HTTP {resp_tx.status_code}): {resp_tx.text}")

                except (GatewayTimeoutError, GatewayConnectionError) as e:
                    # Catch gateway network timeout: perform safe reconciliation using existing idempotency reference
                    log.warning("[%s] Gateway network timeout during transfer (%s). Initiating reconciliation...", self.metadata.id, e)
                    resp_tx_recon = await gateway.get("/api/v1/transactions", token=alex_token)
                    self._record_response(summary, resp_tx_recon, "alex.morgan")
                    if resp_tx_recon.is_success:
                        matching_tx = next((t for t in resp_tx_recon.json() if t.get("reference") == ref), None)
                        if matching_tx and matching_tx.get("status") == "COMPLETED":
                            log.info("[%s] Safe reconciliation confirmed completed transfer %s after timeout", self.metadata.id, matching_tx.get("id"))
                            tx_data = matching_tx
                    if not tx_data:
                        raise RuntimeError(
                            f"Step D failed: Network timeout occurred and reconciliation did not confirm "
                            f"completion for reference {ref}. Retained Idempotency-Key: {idem_key}"
                        ) from e

                tx_id = str(tx_data["id"])
                self.created_resources["transaction_id"] = tx_id
                self.created_resources["transaction_reference"] = ref

                # Validate transfer response fields
                if str(tx_data.get("customerId", "")).lower() != alex_id.lower():
                    raise RuntimeError("Step D failed: Transfer customerId mismatch")
                if str(tx_data.get("sourceAccountId", "")).lower() != account_id.lower():
                    raise RuntimeError("Step D failed: Transfer sourceAccountId mismatch")
                if str(tx_data.get("beneficiaryId", "")).lower() != beneficiary_id.lower():
                    raise RuntimeError("Step D failed: Transfer beneficiaryId mismatch")
                if Decimal(str(tx_data.get("amount"))) != transfer_amt:
                    raise RuntimeError("Step D failed: Transfer amount mismatch")
                if tx_data.get("currency") != flow_cfg.transfer_currency:
                    raise RuntimeError("Step D failed: Transfer currency mismatch")
                if tx_data.get("status") != "COMPLETED":
                    raise RuntimeError(f"Step D failed: Transfer status is '{tx_data.get('status')}', expected 'COMPLETED'")

                self.created_resources["transaction_status"] = "COMPLETED"

                # Step E: Single Transaction Retrieval & Validation
                resp_single_tx = await gateway.get(f"/api/v1/transactions/{tx_id}", token=alex_token)
                self._record_response(summary, resp_single_tx, "alex.morgan")
                if not resp_single_tx.is_success:
                    raise RuntimeError(f"Step E failed: Could not retrieve transaction {tx_id} (HTTP {resp_single_tx.status_code})")

                single_tx = resp_single_tx.json()
                if single_tx.get("status") != "COMPLETED":
                    raise RuntimeError(f"Step E failed: Transaction record returned non-COMPLETED status: {single_tx.get('status')}")

                # Step E: Post-Transfer Balance Decrement Verification (Using Decimal arithmetic)
                resp_post_bal = await gateway.get(f"/api/v1/accounts/{account_id}/balance", token=alex_token)
                self._record_response(summary, resp_post_bal, "alex.morgan")
                if not resp_post_bal.is_success:
                    raise RuntimeError(f"Step E failed: Could not retrieve post-transfer balance (HTTP {resp_post_bal.status_code})")

                post_bal_data = resp_post_bal.json()
                post_balance = Decimal(str(post_bal_data.get("availableBalance")))
                expected_balance = initial_balance - transfer_amt
                if post_balance != expected_balance:
                    raise RuntimeError(
                        f"Step E failed: Post-transfer balance mismatch. "
                        f"Initial: {initial_balance}, Transfer: {transfer_amt}, "
                        f"Expected: {expected_balance}, Actual: {post_balance}"
                    )

                self.created_resources["post_balance"] = str(post_balance)
                log.info("[%s] Verified balance decreased exactly: %s -> %s %s", self.metadata.id, initial_balance, post_balance, flow_cfg.transfer_currency)

            # ------------------------------------------------------------------
            # Step E (Cont.): Transaction History Inquiry for Alex
            # ------------------------------------------------------------------
            log.info("[%s] Querying transaction list for Alex", self.metadata.id)
            resp_txs = await gateway.get("/api/v1/transactions", token=alex_token)
            self._record_response(summary, resp_txs, "alex.morgan")
            if not resp_txs.is_success:
                raise RuntimeError(f"Step E failed: Querying transactions failed (HTTP {resp_txs.status_code})")

            # ------------------------------------------------------------------
            # Step F: Sam Taylor's Independent Journey (Separate Identity Token)
            # ------------------------------------------------------------------
            log.info("[%s] Step F: Authenticating as Sam Taylor and performing independent inquiry...", self.metadata.id)
            sam_token = await auth.get_access_token("sam.taylor", sam_pass)

            # Sam checks own profile
            resp_sam_prof = await gateway.get(f"/api/v1/customers/{sam_id}/profile", token=sam_token)
            self._record_response(summary, resp_sam_prof, "sam.taylor")
            if not resp_sam_prof.is_success:
                raise RuntimeError(f"Step F failed: Sam Taylor profile lookup failed (HTTP {resp_sam_prof.status_code})")

            # Sam lists own accounts
            resp_sam_accts = await gateway.get("/api/v1/accounts", token=sam_token)
            self._record_response(summary, resp_sam_accts, "sam.taylor")
            if not resp_sam_accts.is_success:
                raise RuntimeError(f"Step F failed: Sam Taylor accounts listing failed (HTTP {resp_sam_accts.status_code})")

            sam_accounts = resp_sam_accts.json()
            if isinstance(sam_accounts, list) and len(sam_accounts) > 0:
                sam_acct_id = str(sam_accounts[0]["id"])
                resp_sam_bal = await gateway.get(f"/api/v1/accounts/{sam_acct_id}/balance", token=sam_token)
                self._record_response(summary, resp_sam_bal, "sam.taylor")

            # Finalize success status
            summary.status = ExecutionStatus.SUCCESS

        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(str(e))
            log.error("[%s] Scenario execution halted: %s", self.metadata.id, e)
            raise

        finally:
            summary.finished_at = datetime.now(timezone.utc)
            # Attach fully traceable manifest
            manifest = self._compile_manifest(summary)
            summary.run_manifest = manifest

        log.info(
            "[%s] Completed benign customer journey (dry_run=%s): %d total requests, %d success, %d failed",
            self.metadata.id, self.dry_run, summary.total_requests, summary.successful_requests, summary.failed_requests,
        )

        return summary
