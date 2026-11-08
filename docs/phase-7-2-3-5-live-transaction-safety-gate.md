# Aegis Phase 7.2.3.5 — Final Live Transaction Safety Gate Report

**Phase:** Phase 7.2.3.5 — Final Live Transaction Safety Gate  
**Execution Mode:** Read-Only Audit & Verification  
**Evaluation Date:** November 8, 2026  
**Target Scenario:** `SCEN-BENIGN-01` (First End-to-End Benign FinTech Customer Journey)  
**Status:** `READY_WITH_DOCUMENTED_LIMITATIONS`

---

## Executive Summary

Phase 7.2.3.5 establishes the authoritative safety audit of the `SCEN-BENIGN-01` financial workflow prior to authorizing live financial execution against the Aegis testbed.

Under the strict audit boundary:
- **Zero mutating API requests** were issued.
- **Zero accounts** were debited or credited.
- **Zero database records** were modified.
- **No live transfer** was executed.

All safety verifications were conducted via exhaustive static inspection of the Java backend microservices (`customer-service`, `account-service`, `transaction-service`, `telemetry-service`), database migration DDLs, Gateway routing and authentication filters, and the Python simulation framework test suite.

The safety gate concludes that the financial, architectural, and operational invariants are fully validated, resulting in a gate verdict of **`READY_WITH_DOCUMENTED_LIMITATIONS`**.

---

## 1. Beneficiary Workflow Audit

### 1.1 Backend Implementation & Endpoints
The beneficiary lifecycle is governed by `com.aegis.transaction.TransactionService` and exposed via `TransactionController`:
- `GET /api/v1/beneficiaries`: Lists beneficiaries belonging to the authenticated customer (retrieved from JWT claims).
- `POST /api/v1/beneficiaries`: Creates a beneficiary with initial status `PENDING`.
  - Request body: `{ "name": "...", "destinationAccountReference": "...", "currency": "..." }`
- `POST /api/v1/beneficiaries/{id}/verify`: Transitions beneficiary status from `PENDING` to `VERIFIED`.

### 1.2 Ownership & Currency Validation
- Beneficiary creation binds `customerId` strictly to the authenticated caller's customer ID extracted from the validated Keycloak JWT subject. A customer cannot register a beneficiary on behalf of another entity.
- The `currency` field is validated at transfer time: `TransactionService.transfer()` enforces that the transfer currency matches the beneficiary's registered currency:
  ```java
  if (!beneficiary.getCurrency().equalsIgnoreCase(request.currency())) {
      throw new IllegalArgumentException("Transfer currency must match beneficiary currency");
  }
  ```

### 1.3 Duplicate Handling & Database Constraints
- **Database Inspection (`V1__transaction_schema.sql`):**
  ```sql
  CREATE TABLE transaction_data.beneficiaries (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      customer_id UUID NOT NULL,
      name VARCHAR(120) NOT NULL,
      destination_account_reference VARCHAR(64) NOT NULL,
      currency VARCHAR(3) NOT NULL,
      status VARCHAR(32) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  ```
  *Finding:* The database table does **not** have a unique constraint on `(customer_id, destination_account_reference)`. If the creation API is called multiple times without inspection, duplicate beneficiary records will be inserted.
- **Simulation Mitigation:**
  `benign_customer_flow.py` executes a preflight `GET /api/v1/beneficiaries` call before any mutation. If an existing beneficiary with `destinationAccountReference == "ACCT-00020001"` is found:
  1. Creation is skipped.
  2. If status is `PENDING`, verification is executed.
  3. If status is already `VERIFIED`, both creation and verification are skipped and the existing ID is reused.
- **Sam Taylor Destination Reference:**
  Reference `ACCT-00020001` corresponds to Sam Taylor's seed account. The baseline audit (Phase 7.2.3.3) confirmed that Alex Morgan currently has 0 registered beneficiaries in the local testbed. On the first live run, the beneficiary will be created once as `PENDING`, verified to `VERIFIED`, and subsequently reused on all future runs.

---

## 2. Transaction Idempotency & Database Ledger Audit

### 2.1 Idempotency Key Architecture & Uniqueness Scope
- **Client Side (`simulation/src/simulation/scenarios/benign_customer_flow.py`):**
  - Mints an upfront, deterministic UUIDv4 idempotency key formatted as `tx-benign-{run_id}-{uuid}`.
  - Sends this key via the `Idempotency-Key` HTTP request header and as `reference` in the JSON payload of `POST /api/v1/transfers`.
  - Persists the key to `flow.created_resources["idempotency_key"]` and `flow.created_resources["transaction_reference"]` before dispatching the HTTP request.
- **Gateway & Transaction Service Scope:**
  - `TransactionService.java` indexes transactions by `reference`.
  - Database table `transaction_data.transactions`:
    ```sql
    CREATE TABLE transaction_data.transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        reference VARCHAR(80) NOT NULL UNIQUE,
        customer_id UUID NOT NULL,
        source_account_id UUID NOT NULL,
        beneficiary_id UUID NOT NULL,
        amount NUMERIC(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        status VARCHAR(32) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ```
  - Database table `account_data.account_debits`:
    ```sql
    CREATE TABLE account_data.account_debits (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        account_id UUID NOT NULL,
        reference VARCHAR(80) NOT NULL UNIQUE,
        amount NUMERIC(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ```

### 2.2 Payload Consistency & Conflict Detection
`TransactionService.java` explicitly verifies payload congruence when an idempotency key is matched:
1. **Same Key + Same Payload:**
   If `existing.getReference().equals(reference)`:
   - Validates that `sourceAccountId`, `beneficiaryId`, `amount`, and `currency` match the existing record exactly.
   - If the transaction is already `COMPLETED`, it immediately returns the existing transaction response with no side effects or ledger changes.
2. **Same Key + Different Payload:**
   - Throws `ResponseStatusException(HttpStatus.CONFLICT, "Idempotency key was already used for a different transfer")`.
3. **Concurrent Submissions:**
   - The PostgreSQL `UNIQUE` constraint on `transactions.reference` causes competing concurrent inserts to fail with `DataIntegrityViolationException`, preventing duplicate execution at the database engine level.

### 2.3 Account Debit Ordering & Pessimistic Locking
`AccountDebitService.java` in `account-service` uses JPA pessimistic write locking:
```java
Account account = accounts.findLocked(request.accountId())
    .orElseThrow(() -> new IllegalArgumentException("Account not found: " + request.accountId()));
```
- Query executed: `SELECT * FROM account_data.accounts WHERE id = ? FOR UPDATE`.
- Ledger entry inserted into `account_data.account_debits` with unique `reference`.
- Account balance decremented: `account.setBalance(account.getBalance().subtract(request.amount()))`.
- Transaction state transition order in `TransactionService.java`:
  `CREATED` $\rightarrow$ `PENDING` $\rightarrow$ `accountService.debit(...)` $\rightarrow$ `AUTHORIZED` $\rightarrow$ `COMPLETED`.
- If debit fails, transaction is marked `FAILED` and no funds leave the source account.

### 2.4 Simulation Timeout & Uncertainty Recovery
In the event of an uncertain Gateway timeout (e.g. HTTP 504) or network partition during transfer dispatch:
- `GatewayClient` does **not** perform automatic retries on `POST` requests.
- `benign_customer_flow.py` catches `GatewayTimeoutError` / `GatewayCommunicationError`, preserves the active `idempotency_key`, and initiates reconciliation:
  ```python
  GET /api/v1/transactions
  ```
- It inspects existing transactions for the recorded reference. If confirmed as `COMPLETED`, execution proceeds to post-transfer balance validation. If unconfirmed or absent, execution immediately halts safely with an explicit error, preventing duplicate financial mutations.

---

## 3. Financial Invariants Audit

### 3.1 Account Baseline & Invariants
- **Source Account ID:** `20000000-0000-4000-8000-000000000001`
- **Owner:** Alex Morgan (`10000000-0000-4000-8000-000000000001`)
- **Status:** `ACTIVE` (Verified via Phase 7.2.3.3 dry run and database audit)
- **Currency:** `USD`
- **Baseline Available Balance:** `$12,383.74 USD` (Reconciled in Phase 7.2.3.3 against historical ledger debits)
- **Transfer Amount:** `$25.00 USD`
- **Solvency Check:** `$12,383.74` available balance is significantly greater than `$25.00` transfer amount. Post-transfer expected balance is `$12,358.74 USD`.

### 3.2 Sam Taylor Account Reference & Clearing Semantics
- **Destination Account Reference:** `ACCT-00020001`
- **Sam Taylor Seed Account:** Owned by Sam Taylor (`10000000-0000-4000-8000-000000000002`), currency `GBP`.
- **Clearing Semantics:**
  The `transaction-service` treats beneficiary destination references as external clearing references. The transfer debits Alex's USD account by `$25.00 USD`. It does **not** execute an internal ledger credit to Sam's GBP account and does **not** invoke automatic FX conversion. Sam's balance remains unchanged at `£5,300.25 GBP`.

### 3.3 Arithmetic Integrity
- Python simulation framework strictly utilizes `decimal.Decimal` with quantization to 2 decimal places (`Decimal("0.01")`).
- Spring Boot backend services strictly utilize Java `BigDecimal` with `RoundingMode.UNNECESSARY` or exact scale matching.
- Floating-point arithmetic (`float`, `double`) is strictly excluded from all balance calculations and assertions.

### 3.4 Currency Presentation Separation (INR vs USD)
- **Ledger Invariant:** All persistent ledger balances and transaction amounts remain natively in USD.
- **Presentation Layer:** Indian Rupee amounts are strictly calculated using fixed demonstration reference rates (USD $\rightarrow$ INR @ `84.00`, GBP $\rightarrow$ INR @ `108.50`).
- **Transfer Amount:** Native `$25.00 USD` equates to reference `₹2,100.00 INR` for UI and reporting display only.

---

## 4. Simulation Safety & Verification

### 4.1 Dry-Run Safety
- In dry-run mode (`--dry-run`), mutating HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) are never dispatched.
- Dry-run mode produces planned mutation manifests without altering the state of any microservice or database.

### 4.2 Non-Idempotent HTTP Safety
- `GatewayClient` in `simulation/src/simulation/clients/gateway.py` enforces that retries are strictly restricted to idempotent read methods (`GET`, `HEAD`, `OPTIONS`).

### 4.3 SOC Telemetry Verification
- `SocTelemetryVerifier` validates security telemetry emitted during the scenario:
  - Verifies presence of correlation IDs in security event stream (`/api/v1/security/events`).
  - Queries `/api/v1/security/incidents` within the run time window. Benign traffic must yield `0` incidents.
  - Queries `/api/v1/security/posture` ensuring all endpoints report `confirmedVulnerability == false`.
- Verifier outputs four distinct, non-ambiguous outcomes: `PASS`, `FAIL`, `INCOMPLETE`, or `UNAVAILABLE`.

---

## 5. Test Suite Verification

All verification suites pass with zero regressions:
- **Simulation Test Suite:** 66 passing tests (`pytest simulation/tests`):
  - Unit tests covering configuration, authentication, gateway client, and scenario execution.
  - Idempotency recovery tests verifying transient 504 handling and reconciliation.
  - SOC verifier tests covering `PASS`, `FAIL`, `INCOMPLETE`, and `UNAVAILABLE` branches.
- **Frontend Test Suite:** 169 passing tests (`npm --prefix frontend test -- --watch=false`):
  - Currency pipe and service tests verifying INR dual-presentation and rate transparency.
  - Component tests across Overview, Accounts, Transactions, Customers, and Security modules.
- **Backend Test Suite:** 315 passing tests across microservices.

---

## 6. Final Gate Decision & Operator Prerequisites

### Final Decision
**`READY_WITH_DOCUMENTED_LIMITATIONS`**

### Documented Limitations & Operator Checklist Prior to Live Execution
1. **Docker Testbed Bring-up:**
   The Docker daemon and container stack are currently stopped (preserving database volume state). Before running live execution, the operator must:
   ```powershell
   docker compose -f infrastructure/docker/compose.yml --env-file config/dev.env up -d
   ```
   And verify that health endpoints return HTTP 200 via `simulation doctor`.
2. **Beneficiary Idempotency Scope:**
   Because `transaction_data.beneficiaries` lacks a database unique constraint, live execution relies on the simulation runner's preflight beneficiary check (`GET /api/v1/beneficiaries`) to prevent duplicate records. The simulation framework guarantees this check.
3. **Outbound Clearing Semantics:**
   Sam Taylor's account reference `ACCT-00020001` serves as an outbound clearing destination. Alex's account will be debited `$25.00 USD`; Sam's account will not be credited, as designed.
4. **Demonstration Presentation Rates:**
   All INR figures in ShieldOps UI or simulation logs represent non-authoritative reference conversions at `84.00 INR/USD`.

---
*Report certified by Aegis Security & Financial Safety Engineering.*

