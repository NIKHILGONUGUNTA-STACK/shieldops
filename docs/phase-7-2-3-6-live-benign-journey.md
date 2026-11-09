# Aegis Phase 7.2.3.6 — Controlled Live Benign Customer Journey Report

**Phase:** Phase 7.2.3.6 — Controlled Live Benign Customer Journey  
**Scenario ID:** `SCEN-BENIGN-01` (Legitimate Customer Banking Journey)  
**Execution Timestamp:** 2026-11-08T16:34:15.572Z – 2026-11-08T16:34:18.050Z (Duration: 2.48s)  
**Execution Mode:** `LIVE LOCAL EXECUTION` (Authorized mutating FinTech simulation)  
**Target Gateway:** `http://localhost:8000`  
**Run ID:** `dc10a375-bdb4-43b7-a07e-5cafd0087a34`  
**Execution Status:** `SUCCESS` (15/15 requests successful, 0 errors)  
**SOC Verification Outcome:** `INCOMPLETE` (Wire telemetry: 15/15 PASS, Incidents: 0 PASS, Posture/Reconciliation: INCOMPLETE due to legacy container build)

---

## Executive Summary

Phase 7.2.3.6 represents the first authorized live financial simulation executed through the Aegis Gateway against the containerized local FinTech testbed.

Under strictly bounded execution limits:
- **Exactly one outbound financial transfer** of **$25.00 USD** was executed.
- The transfer debited Alex Morgan's source account (`20000000-0000-4000-8000-000000000001`).
- The source account balance transitioned from **$12,383.74 USD** to **$12,358.74 USD**.
- The beneficiary destination reference (`ACCT-00020001`) was cleared as an external reference; Sam Taylor's GBP account balance remained untouched at **£5,300.25 GBP**.
- The upfront idempotency key (`2720bdd4-a41b-42f9-b928-f81ff5aa04ce`) was persisted prior to the transfer request and uniquely indexed in both transaction and debit tables.
- **15 of 15** wire telemetry correlation IDs were successfully ingested and queried by the security analyst identity.
- **Zero false positive security incidents** were generated.

---

## 1. Execution Identifiers & Manifest

| Parameter | Value |
| :--- | :--- |
| **Run ID** | `dc10a375-bdb4-43b7-a07e-5cafd0087a34` |
| **Scenario** | `SCEN-BENIGN-01` |
| **Mode** | `LIVE LOCAL EXECUTION` (`--execute`) |
| **Identities Authenticated** | `alex.morgan` (Customer), `sam.taylor` (Inquiry), `analyst` (SOC Verification) |
| **Source Account ID** | `20000000-0000-4000-8000-000000000001` (Alex Morgan) |
| **Beneficiary ID** | `6a4484af-8496-4bb7-b3b0-e49ee5e8efec` (Sam Taylor) |
| **Beneficiary Status** | `VERIFIED` |
| **Destination Reference** | `ACCT-00020001` |
| **Idempotency Key** | `2720bdd4-a41b-42f9-b928-f81ff5aa04ce` |
| **Transaction Reference** | `BENIGN-TX-D326FF5EAC26` |
| **Transaction ID** | `5a9be0d7-b99a-4922-b66b-4a04b40e7d24` |
| **Transaction Status** | `COMPLETED` |
| **Transfer Amount** | **$25.00 USD** |
| **Reference Rate** | `84.00 INR/USD` (Demonstration rate, non-authoritative) |
| **Demonstration Equivalent** | **₹2,100.00 INR** |
| **Manifest Path** | `simulation/reports/run-20261108-163419-scen-benign-01.json` |

---

## 2. Financial Ledger & Balance Audit

### 2.1 Source Account (Alex Morgan)
- **Account Number:** `ACCT-00010001`
- **Currency:** `USD`
- **Initial Available Balance:** `$12,383.74 USD` (≈ ₹10,40,234.16 INR)
- **Actual Debit:** `$25.00 USD` (≈ ₹2,100.00 INR)
- **Resulting Balance:** **$12,358.74 USD** (≈ ₹10,38,134.16 INR)
- **PostgreSQL Ledger Verification:**
  ```sql
  SELECT id, account_number, currency, balance, status FROM account_data.accounts WHERE id = '20000000-0000-4000-8000-000000000001';
  -- Result: 20000000-0000-4000-8000-000000000001 | ACCT-00010001 | USD | 12358.7400 | ACTIVE
  ```
- **Debit Table Entry (`account_data.account_debits`):**
  ```sql
  SELECT id, account_id, reference, amount, currency, created_at FROM account_data.account_debits WHERE reference = '2720bdd4-a41b-42f9-b928-f81ff5aa04ce';
  -- Result: e0be1978-8d25-4938-b116-ac0a837e9847 | 20000000-0000-4000-8000-000000000001 | 2720bdd4-a41b-42f9-b928-f81ff5aa04ce | 25.0000 | USD | 2026-11-08 16:34:17.603901+00
  ```

### 2.2 Destination Account (Sam Taylor)
- **Account Number:** `ACCT-00020001`
- **Currency:** `GBP`
- **Balance Prior to Run:** `£5,300.25 GBP`
- **Balance After Run:** `£5,300.25 GBP` (Completely unchanged)
- **Clearing Semantics Confirmation:**
  The destination reference was treated as an external clearing identifier. No internal credit or automated FX conversion was performed on Sam's ledger, confirming system boundary integrity.

---

## 3. Dispatched HTTP Request & Response Trace (Secrets Redacted)

Total HTTP business requests: **15** (13 returned HTTP 200, 2 returned HTTP 201). All Bearer JWTs and credentials are redacted.

| # | Method | URL Path | Status | Latency | Identity | Correlation ID |
| :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `GET` | `/api/v1/customers/10000000-0000-4000-8000-000000000001` | 200 | 336.4ms | `alex.morgan` | `5221c346-f035-4fad-b23c-852b1a1d0605` |
| 2 | `GET` | `/api/v1/customers/10000000-0000-4000-8000-000000000001/profile` | 200 | 35.1ms | `alex.morgan` | `7a2b1909-a02a-403f-8485-c69bf259bf2f` |
| 3 | `GET` | `/api/v1/accounts` | 200 | 44.2ms | `alex.morgan` | `c06c965a-8377-4983-9104-8f5a05861886` |
| 4 | `GET` | `/api/v1/accounts/20000000-0000-4000-8000-000000000001` | 200 | 62.7ms | `alex.morgan` | `094f7f6a-c218-4c52-8912-d2ebdb16bfe8` |
| 5 | `GET` | `/api/v1/accounts/20000000-0000-4000-8000-000000000001/balance` | 200 | 32.1ms | `alex.morgan` | `c842af05-ab12-430b-9d32-e2bf3bf01450` |
| 6 | `GET` | `/api/v1/beneficiaries` | 200 | 42.1ms | `alex.morgan` | `40727291-5051-4e82-9ddc-04294944afd0` |
| 7 | `POST` | `/api/v1/beneficiaries` | 201 | 335.7ms | `alex.morgan` | `3c60624f-f519-4879-a738-f274c2d26897` |
| 8 | `POST` | `/api/v1/beneficiaries/6a4484af-8496-4bb7-b3b0-e49ee5e8efec/verify` | 200 | 70.5ms | `alex.morgan` | `483fa997-700d-45dd-ad24-66c1e92fc9c0` |
| 9 | `POST` | `/api/v1/transfers` | 201 | 733.2ms | `alex.morgan` | `c2cc7a33-07ae-4723-8a75-6b49de814f3f` |
| 10 | `GET` | `/api/v1/transactions/5a9be0d7-b99a-4922-b66b-4a04b40e7d24` | 200 | 28.6ms | `alex.morgan` | `d7f52477-2afd-45c9-b802-3652ae893cd3` |
| 11 | `GET` | `/api/v1/accounts/20000000-0000-4000-8000-000000000001/balance` | 200 | 24.5ms | `alex.morgan` | `c71fa182-033a-44f3-80c6-aaa75cd3a5a2` |
| 12 | `GET` | `/api/v1/transactions` | 200 | 38.2ms | `alex.morgan` | `22101fbd-3b7d-4ebd-8453-b4d79ad4b047` |
| 13 | `GET` | `/api/v1/customers/10000000-0000-4000-8000-000000000002/profile` | 200 | 29.3ms | `sam.taylor` | `79888e65-bbaf-4ead-88be-d2cac2baadb4` |
| 14 | `GET` | `/api/v1/accounts` | 200 | 30.8ms | `sam.taylor` | `a40ddbb2-baa8-43a4-a45e-fc9f881be2d7` |
| 15 | `GET` | `/api/v1/accounts/20000000-0000-4000-8000-000000000003/balance` | 200 | 29.9ms | `sam.taylor` | `622b0028-89c6-4af7-a507-05bd7e09c875` |

---

## 4. SOC Telemetry & Invariant Verification

Verification was performed immediately following business execution using the authorized `analyst` identity.

| Assertion | Expected Invariant | Observed Result | Classification |
| :--- | :--- | :--- | :---: |
| **Gateway Wire Telemetry** | All correlation IDs ingested in Redis / Security Events | **15/15** correlation IDs matched in `/api/v1/security/events` | **PASS** |
| **Security Incidents** | Zero unexpected incidents attributed to benign customer flow | **0** new incidents flagged | **PASS** |
| **Security Reconciliation** | Reconciliation summary endpoint returns summary payload | Endpoint returned HTTP 404 (running container pre-dates Phase 7.1 build) | **INCOMPLETE** |
| **Security Posture** | `confirmedVulnerability == false` on all endpoints across pages | Endpoint returned HTTP 404 (running container pre-dates Phase 7.1 build) | **INCOMPLETE** |
| **Overall Telemetry Outcome** | Business execution clean, telemetry partially observable | Categorized as `INCOMPLETE` without marking business flow failed | **INCOMPLETE** |

> [!NOTE]
> In accordance with the Phase 7.2.3.6 requirements, **incomplete telemetry endpoints are classified separately from business execution**. The business financial workflow passed 100% with full transactional and ledger integrity.

---

## 5. Summary of Invariants Verified

1. **Authorization Boundary:** Executed strictly against local testbed (`http://localhost:8000`), zero external network calls.
2. **Transfer Bounds:** Exactly 1 transfer of $25.00 USD, zero automatic POST retries.
3. **Idempotency Integrity:** Deterministic UUID `2720bdd4-a41b-42f9-b928-f81ff5aa04ce` recorded in both `transaction_data.transactions` and `account_data.account_debits`.
4. **Beneficiary Lifecycle:** Handled safely via preflight check, created, verified to `VERIFIED`, and stored for reuse.
5. **Ledger Decoupling:** Alex's USD account debited exactly $25.00 USD; Sam's GBP account untouched.
6. **Telemetry Correlation:** 15/15 correlation IDs queryable by SOC analyst.

---
*Report certified by Aegis FinTech & Security Engineering.*

