# Aegis Phase 7.2.3.1 — First End-to-End Benign FinTech Customer Journey (`SCEN-BENIGN-01`)

**Document Version:** 1.0.0  
**Status:** Completed & Verified  
**Date:** 2026-11-04  
**Scenario ID:** `SCEN-BENIGN-01`  
**Vector Category:** `BENIGN`  
**Test Suite:** `simulation/tests/test_benign_customer_flow.py` (41 passing Python unit tests total)

---

## 1. Executive Summary & Objective

In Phase 7.2.3.1, Aegis achieves its first executable end-to-end FinTech customer simulation scenario, `SCEN-BENIGN-01`. Operating within the Python simulation framework established in Phase 7.2.2, this scenario models a realistic, legitimate multi-customer banking journey through the Aegis Gateway.

The scenario exercises the Customer, Account, and Transaction microservices using actual Keycloak OIDC tokens, verifies idempotency and state transitions, and concludes with automated SOC telemetry and security invariant verification using an independent security analyst identity.

### Scope Compliance
- **Legitimate Workflows Only:** No adversary payloads, credential stuffing, injection, or BOLA attacks were included.
- **Microservice Port Isolation:** All business interactions are routed exclusively through the Aegis Gateway (`http://localhost:8000`).
- **No Direct Database Writes:** All data mutations (beneficiary creation, transfer, balance debit) occur through the published REST APIs.
- **Offline Mocked Verification:** Verified 100% pass via 41 mocked unit tests. Live container execution is safely gated behind the `--execute` flag and documented as deferred when Docker services are offline.

---

## 2. Customer Identities & Authentication Architecture

The journey leverages the authoritative identities pre-provisioned in Keycloak (`aegis-dev` realm) and PostgreSQL (`customer_data.customers`):

| Persona | Keycloak Username | Customer ID | Account Reference | Assigned Role | Usage in Scenario |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Alex Morgan** | `alex.morgan` | `10000000-0000-4000-8000-000000000001` | `ACCT-00010001` | `CUSTOMER` | Source account owner, beneficiary creator, payment sender |
| **Sam Taylor** | `sam.taylor` | `10000000-0000-4000-8000-000000000002` | `ACCT-00020001` | `CUSTOMER` | Destination beneficiary, independent read-only inquirer |
| **SOC Operator** | `analyst` | *(none)* | *(none)* | `SECURITY_ANALYST` | Authorized SOC API verification |

### Token Separation & Security Invariants
1. **Separate Tokens:** Alex and Sam acquire independent JWT access tokens via `KeycloakAuthManager` using OAuth2 Direct Access Grants (`password` grant).
2. **Zero Token Crossover:** Alex's token is never used for Sam's requests, and Sam's token is never used for Alex's requests.
3. **No Credential Exposure:** Passwords and access tokens are strictly masked (`***[REDACTED]***`) and excluded from execution reports, CLI outputs, and logs.

---

## 3. End-to-End Scenario Workflow

```
[Keycloak OIDC]
       │  (Password Grant)
       ▼
 [Alex Morgan] ──(Bearer Token 1)──► [Aegis Gateway:8000]
                                              │
               ┌──────────────────────────────┼──────────────────────────────┐
               ▼                              ▼                              ▼
      [Customer Service]              [Account Service]            [Transaction Service]
      Step A: Profile Lookup          Step B: List Accounts        Step C: Beneficiary Setup
                                              Balance Inquiry      Step D: Transfer Execution
                                                                   Step E: Transaction History
                                              │
 [Sam Taylor]  ──(Bearer Token 2)──► [Aegis Gateway:8000]
                                              │
               ┌──────────────────────────────┘
               ▼
      Step F: Independent Profile & Account Inquiry
```

### Step A — Customer Profile Verification
1. Alex queries own customer record: `GET /api/v1/customers/10000000-0000-4000-8000-000000000001`.
2. Alex queries own profile: `GET /api/v1/customers/10000000-0000-4000-8000-000000000001/profile`.
3. Validates HTTP 200 responses, `customerNumber: "CUST-10001"`, and active status.

### Step B — Account Discovery & Balance Inquiry
1. Alex lists accounts: `GET /api/v1/accounts`.
2. Inspects returned accounts dynamically: selects active account `20000000-0000-4000-8000-000000000001` (`ACCT-00010001`, currency `USD`, balance $\ge \$25.00$).
3. Queries account details: `GET /api/v1/accounts/{accountId}`.
4. Queries real-time balance: `GET /api/v1/accounts/{accountId}/balance`.

### Step C — Beneficiary Management
1. Queries existing beneficiaries: `GET /api/v1/beneficiaries`.
2. **Idempotent Reuse:** Checks whether a beneficiary with destination reference `ACCT-00020001` and currency `USD` already exists:
   - If present and in status `VERIFIED`: Reuses existing beneficiary ID without creating a duplicate.
   - If present and in status `PENDING`: Verifies via `POST /api/v1/beneficiaries/{id}/verify`.
   - If absent: Creates new beneficiary via `POST /api/v1/beneficiaries` (`name: "Sam Taylor"`, `destinationAccountReference: "ACCT-00020001"`, `currency: "USD"`), followed immediately by verification via `POST /api/v1/beneficiaries/{id}/verify`.

### Step D — Financial Transfer Execution
1. Generates unique reference (`BENIGN-TX-<10_HEX>`) and idempotency key (`IDEM-<16_HEX>`).
2. Submits transfer:
   ```http
   POST /api/v1/transfers HTTP/1.1
   Host: localhost:8000
   Authorization: Bearer <alex_jwt>
   X-Correlation-Id: <uuid>
   Idempotency-Key: IDEM-4828F4D09110AB12
   Content-Type: application/json

   {
     "customerId": "10000000-0000-4000-8000-000000000001",
     "sourceAccountId": "20000000-0000-4000-8000-000000000001",
     "beneficiaryId": "30000000-0000-4000-8000-000000000001",
     "amount": 25.00,
     "currency": "USD",
     "reference": "BENIGN-TX-D8F9A102B4"
   }
   ```
3. Validates HTTP 201 Created response and status `COMPLETED`.
4. Re-queries account balance (`GET /api/v1/accounts/{id}/balance`) to confirm balance deduction.
5. **No Automatic Retry Rule:** In accordance with financial safety requirements, financial POST operations are never automatically retried.

### Step E — Transaction History & Receipt Verification
1. Alex retrieves transaction history: `GET /api/v1/transactions`.
2. Retrieves individual transaction record: `GET /api/v1/transactions/{transactionId}`.
3. Asserts ownership, amount ($25.00), currency (`USD`), and completed status.

### Step F — Sam Taylor's Independent Journey
1. Authenticates as Sam Taylor (`sam.taylor`) with distinct bearer credentials.
2. Performs read-only inquiries:
   - Profile: `GET /api/v1/customers/10000000-0000-4000-8000-000000000002/profile`
   - Accounts: `GET /api/v1/accounts`
   - Balance: `GET /api/v1/accounts/{sam_accountId}/balance`
3. Verifies zero leakage of Alex's account data to Sam.

---

## 4. Post-Execution SOC Verification

Following the business requests, the simulation executes independent validation using a `SECURITY_ANALYST` identity via [`SocTelemetryVerifier`](file:///c:/Users/nikhi/aegis/simulation/src/simulation/scenarios/soc_verifier.py):

| Verification Check | Target Endpoint | Assertion / Invariant |
| :--- | :--- | :--- |
| **Telemetry Ingestion** | `GET /api/v1/security/events?correlationId={cid}` | Bounded async polling asserts that all recorded request correlation IDs appear in the telemetry store. |
| **Zero False Positives** | `GET /api/v1/security/incidents?from={start}&to={end}` | Asserts that zero security incidents (`RULE-BOLA-01`, `RULE-AUTH-01`, etc.) were triggered by this benign customer run. |
| **API Reconciliation** | `GET /api/v1/security/reconciliation` | Asserts summary metrics are accessible and reflect observed documented operations. |
| **Posture Invariant** | `GET /api/v1/security/posture` | Asserts that `confirmedVulnerability: false` holds across all assessed endpoints (strictly advisory). |

---

## 5. Preflight Safeguards & CLI Usage

### Dry-Run Mode (Non-Mutating Preflight)
```powershell
python -m simulation.cli run --scenario SCEN-BENIGN-01 --dry-run
```
- Performs token acquisition, customer profile queries, account inspection, and beneficiary checks.
- **Skips all data mutations:** Does not invoke `POST /api/v1/transfers` or create new beneficiaries.
- Returns status `SUCCESS` with `transfer_status: "SKIPPED_DRY_RUN"`.

### Live Execution Mode (Local Data Mutation)
```powershell
python -m simulation.cli run --scenario SCEN-BENIGN-01 --execute
```
- Requires explicit `--execute` flag. Rejects execution without one of `--dry-run` or `--execute`.
- Emits preflight manifest displaying transfer amount ($25.00 USD), source/destination identities, and target gateway.
- Executes transfer and performs post-execution SOC telemetry verification.

---

## 6. Verification Results

### Unit Test Execution
```
simulation/tests/test_auth.py .......                                   [ 17%]
simulation/tests/test_benign_customer_flow.py .......                   [ 34%]
simulation/tests/test_cli.py ......                                     [ 48%]
simulation/tests/test_config.py .......                                 [ 65%]
simulation/tests/test_gateway_client.py ........                        [ 85%]
simulation/tests/test_scenario_models.py ......                         [100%]
============================== 41 passed in 15.50s =============================
```

### Live Testbed Status
- **Current Runtime Status:** Docker services currently offline (`docker daemon not running`).
- **Deferred Integration Gate:** Real wire traffic generation against live PostgreSQL/Keycloak/Gateway containers is preserved for when the developer starts the compose stack with `docker compose up -d`. All mocked integration contracts are 100% verified.

