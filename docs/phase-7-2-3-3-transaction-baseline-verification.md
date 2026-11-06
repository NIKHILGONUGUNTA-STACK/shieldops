# Aegis Phase 7.2.3.3 — Final Transaction Baseline Verification

**Document Version:** 1.0.0  
**Status:** Audit Completed & Verified (Authorization Gate Intact)  
**Date:** 2026-11-06  
**Scenario ID:** `SCEN-BENIGN-01`  
**Vector Category:** `BENIGN`  

---

## 1. Executive Summary

Phase 7.2.3.3 performs a rigorous, read-only financial baseline audit of the live Aegis testbed prior to the first live transaction execution.

### Key Audit Findings:
1. **Source Account Verified:** Alex Morgan's account `20000000-0000-4000-8000-000000000001` is `ACTIVE`, denominated in `USD`, with an exact current available balance of **`$12,383.74 USD`** (equivalent to **`₹1,040,234.16 INR`**).
2. **Balance Reconciliation Confirmed:** The **`$116.26 USD`** (**`₹9,765.84 INR`**) difference from the initial seed migration (`$12,500.00 USD`) is completely and precisely explained by 20 historical `COMPLETED` transactions executed during Phase 2, 3, and 4 testing.
3. **Destination Clearing Semantics Confirmed:** Sam Taylor's account `ACCT-00020001` (`20000000-0000-4000-8000-000000000003`) is `ACTIVE` with balance **`£5,300.25 GBP`** (equivalent to **`₹575,077.13 INR`**). The transaction service treats the beneficiary destination reference as an outbound wire/ACH clearing routing reference; it does not credit or inspect Sam's underlying ledger currency.
4. **Beneficiary State Audited:** Alex Morgan has 5 existing test beneficiaries, but **none** for `ACCT-00020001`. Step C of the scenario will create and verify this beneficiary.
5. **Idempotency Safety Verified:** The transaction service guarantees that repeated transfer submissions with the same idempotency key and body return the existing `COMPLETED` transaction record without duplicate account debits.

---

## 2. Source Account Audit & Historical Debit Reconciliation

### 2.1 Live Account Inspection (`GET /api/v1/accounts/20000000-0000-4000-8000-000000000001`)

```json
{
  "id": "20000000-0000-4000-8000-000000000001",
  "accountNumber": "ACCT-00010001",
  "customerId": "10000000-0000-4000-8000-000000000001",
  "currency": "USD",
  "balance": 12383.74,
  "status": "ACTIVE",
  "openedAt": "2024-01-16T09:00:00Z",
  "customer": {
    "id": "10000000-0000-4000-8000-000000000001",
    "customerNumber": "CUST-10001",
    "firstName": "Alex",
    "lastName": "Morgan",
    "email": "alex.morgan@example.test",
    "countryCode": "US",
    "status": "ACTIVE"
  }
}
```

- **Current Available Balance:** `$12,383.74 USD` / `₹1,040,234.16 INR` (at reference exchange rate: 1 USD ≈ 84.00 INR).
- **Ownership:** Belongs to Alex Morgan (`10000000-0000-4000-8000-000000000001`).
- **Account Status:** `ACTIVE`.

### 2.2 Reconciliation of Initial Seed Discrepancy ($12,500.00 vs $12,383.74)

Querying Alex's transaction history (`GET /api/v1/transactions`) revealed 21 historical records (20 `COMPLETED`, 1 `PENDING`):

| Transaction Reference | Timestamp (UTC) | Status | Amount (USD) | Amount (INR ₹) | Running Total Debit (USD) |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `synthetic-runtime-check-20261001` | 2026-10-01 04:31:47 | `PENDING` | $25.25 | ₹2,121.00 | $0.00 (Uncompleted) |
| `phase2-smoke-20261004` | 2026-10-04 06:19:06 | `COMPLETED` | $25.25 | ₹2,121.00 | $25.25 |
| `phase2-final-20261004` | 2026-10-04 06:46:00 | `COMPLETED` | $1.01 | ₹84.84 | $26.26 |
| `phase2-verify-f2bdd8ca` | 2026-10-22 04:27:13 | `COMPLETED` | $5.00 | ₹420.00 | $31.26 |
| `e2e-idem-phase3-1648266434` | 2026-10-22 09:33:08 | `COMPLETED` | $5.00 | ₹420.00 | $36.26 |
| `e2e-idem-phase3-1965401976` | 2026-10-22 10:38:04 | `COMPLETED` | $5.00 | ₹420.00 | $41.26 |
| `e2e-idem-phase3-1394591876` | 2026-10-23 04:16:11 | `COMPLETED` | $5.00 | ₹420.00 | $46.26 |
| `e2e-idem-phase3-1957969844` | 2026-10-23 08:41:26 | `COMPLETED` | $5.00 | ₹420.00 | $51.26 |
| `e2e-idem-phase3-2078121719` | 2026-10-23 09:04:22 | `COMPLETED` | $5.00 | ₹420.00 | $56.26 |
| `e2e-idem-phase3-1109105631` | 2026-10-25 15:32:49 | `COMPLETED` | $5.00 | ₹420.00 | $61.26 |
| `e2e-idem-phase3-413170439` | 2026-10-25 17:01:01 | `COMPLETED` | $5.00 | ₹420.00 | $66.26 |
| `e2e-idem-phase3-892892091` | 2026-10-26 04:04:34 | `COMPLETED` | $5.00 | ₹420.00 | $71.26 |
| `e2e-idem-phase3-1397010765` | 2026-10-26 04:46:17 | `COMPLETED` | $5.00 | ₹420.00 | $76.26 |
| `e2e-idem-phase3-1806332110` | 2026-10-26 05:10:27 | `COMPLETED` | $5.00 | ₹420.00 | $81.26 |
| `e2e-idem-phase3-1092467352` | 2026-10-26 11:10:00 | `COMPLETED` | $5.00 | ₹420.00 | $86.26 |
| `e2e-idem-phase3-1072587117` | 2026-10-26 11:59:09 | `COMPLETED` | $5.00 | ₹420.00 | $91.26 |
| `e2e-idem-phase3-905558070` | 2026-10-26 12:50:06 | `COMPLETED` | $5.00 | ₹420.00 | $96.26 |
| `e2e-idem-phase3-378361410` | 2026-10-26 13:01:45 | `COMPLETED` | $5.00 | ₹420.00 | $101.26 |
| `e2e-idem-phase3-1702875626` | 2026-10-27 03:33:18 | `COMPLETED` | $5.00 | ₹420.00 | $106.26 |
| `e2e-idem-phase3-483290875` | 2026-10-27 04:03:28 | `COMPLETED` | $5.00 | ₹420.00 | $111.26 |
| `e2e-idem-phase3-25843992` | 2026-10-27 04:06:08 | `COMPLETED` | $5.00 | ₹420.00 | $116.26 |

$$\text{Initial Seed Balance} = \$12,500.00 \text{ USD} \quad (\approx ₹1,050,000.00 \text{ INR})$$
$$\text{Sum of Completed Debits} = \$116.26 \text{ USD} \quad (\approx ₹9,765.84 \text{ INR})$$
$$\text{Current Available Balance} = \$12,500.00 - \$116.26 = \mathbf{\$12,383.74 \text{ USD}} \quad (\approx \mathbf{₹1,040,234.16 \text{ INR}})$$

The exact penny-level reconciliation confirms that the live database balance is authentic, uncorrupted, and accurately reflects all prior tests.

---

## 3. Destination Reference & Currency Clearing Semantics

### 3.1 Destination Account Verification (`GET /api/v1/accounts`)

Querying Sam Taylor's accounts via Gateway confirmed:
- **Account ID:** `20000000-0000-4000-8000-000000000003`
- **Account Reference:** `ACCT-00020001`
- **Owner:** Sam Taylor (`10000000-0000-4000-8000-000000000002`)
- **Ledger Currency:** `GBP`
- **Current Balance:** `£5,300.25 GBP` (equivalent to **`₹575,077.13 INR`** at reference rate: 1 GBP ≈ 108.50 INR).
- **Status:** `ACTIVE`.

### 3.2 Clearing Semantics Analysis
- The transaction service treats `destinationAccountReference` as an external clearing address rather than an internal intra-bank ledger account.
- In `TransactionService.java`:
  ```java
  // Invariant in TransactionService.java: lines 110-112
  if (!source.currency().equals(request.currency()) || !beneficiary.getCurrency().equals(request.currency())) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Currency mismatch");
  }
  ```
- The transaction service validates:
  1. `source.currency == request.currency` (`USD == USD`)
  2. `beneficiary.currency == request.currency` (`USD == USD`)
  3. `account-service.debit` validates source currency is `USD`.
- The service **does not** credit Sam's GBP ledger account, nor does it perform dynamic FX currency conversion.
- Therefore, creating the beneficiary with currency `USD` and executing the transfer in `USD` will execute cleanly without encountering currency mismatch errors.

---

## 4. Existing Beneficiary Audit

Querying Alex Morgan's existing beneficiaries (`GET /api/v1/beneficiaries`) revealed 5 pre-existing entries:

| Beneficiary ID | Name | Destination Reference | Currency | Status | Created At |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `9d2bac9b-e528-49ca-862a-2575169c7d6f` | Synthetic Runtime Payee | `SYNTHETIC-EXT-0001` | USD | `PENDING` | 2026-10-01T04:18:41Z |
| `863e604a-7108-4b98-ac8a-a3078a68f50b` | Synthetic Runtime Payee | `SYNTHETIC-EXT-0002` | USD | `VERIFIED` | 2026-10-01T04:31:47Z |
| `5f0748c7-d74d-40d4-9d05-5185d493c364` | Synthetic Smoke | `SYNTH-VERIFY-01` | USD | `VERIFIED` | 2026-10-04T06:19:05Z |
| `5e0be950-8d60-4790-8290-c8a25be20133` | Synthetic Smoke Final | `SYNTH-FINAL-01` | USD | `VERIFIED` | 2026-10-04T06:45:59Z |
| `1e00f200-88d9-44e5-88dc-af10392edca4` | Live Hardening Beneficiary | `SYNTH-DEST-999` | USD | `VERIFIED` | 2026-10-22T04:27:12Z |

**Result:** No beneficiary currently exists for reference `ACCT-00020001`. In live execution, Step C will create `Sam Taylor` with `ACCT-00020001` in status `PENDING`, and then call `POST /api/v1/beneficiaries/{id}/verify` to verify it.

---

## 5. Transaction Idempotency & Uncertain-Result Safety

### 5.1 Idempotency Key Semantics
In `TransactionService.java` (lines 67–89):
- The service enforces idempotency using the `reference` column in `transaction_data.transactions`, mapped from the `Idempotency-Key` HTTP header.
- If a client experiences a network timeout or uncertainty during a `POST /api/v1/transfers` request:
  - Resending the request with the **identical** `Idempotency-Key` and transfer body detects the existing transaction record.
  - If `status == "COMPLETED"`, the service immediately returns the existing record without executing another debit.
  - If the payload differs, it returns `HTTP 409 CONFLICT` ("Idempotency key was already used for a different transfer").
- In `GatewayClient`, automatic retries are strictly disabled for POST requests, guaranteeing zero duplicate transactions.

---

## 6. Financial Summary Table (Including Rupees ₹)

| Metric | USD Value | INR (₹) Equivalent | Notes |
| :--- | :---: | :---: | :--- |
| **Initial Seed Balance** | $12,500.00 | ₹1,050,000.00 | Seed migration `V1__account_schema.sql` |
| **Historical Debits (20 completed)** | $116.26 | ₹9,765.84 | Verified in `transaction_data.transactions` |
| **Current Available Balance** | **$12,383.74** | **₹1,040,234.16** | Audited live via `/api/v1/accounts/{id}/balance` |
| **Planned Transfer Amount** | **$25.00** | **₹2,100.00** | Configured bounded transfer |
| **Projected Post-Transfer Balance** | **$12,358.74** | **₹1,038,134.16** | Expected balance after live execution |
| **Sam Taylor Account Balance** | £5,300.25 GBP | ₹575,077.13 | Audited live via Sam's inquiry (1 GBP ≈ 108.50 INR) |

---

## 7. Authorization Boundary

- **Live Execution Command:**
  ```powershell
  python -m simulation.cli run --scenario SCEN-BENIGN-01 --execute
  ```
- **Readiness:** 100% Verified. All preconditions satisfied.
- **Current Status:** Halted at the authorization gate prior to running `--execute`.
