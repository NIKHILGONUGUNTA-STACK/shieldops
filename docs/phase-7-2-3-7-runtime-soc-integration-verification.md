# Aegis Phase 7.2.3.7 — Runtime Alignment and SOC Integration Verification Report

**Phase:** Phase 7.2.3.7 — Runtime Alignment and SOC Integration Verification  
**Evaluation Date:** November 9, 2026  
**Target Gateway:** `http://localhost:8000`  
**Execution Boundary:** Strict Read-Only with respect to business & financial ledger data  
**Final Status:** `READY_FOR_DATA_LEAKAGE_SIMULATION`

---

## Executive Summary

Phase 7.2.3.7 investigated and resolved the runtime discrepancy reported during Phase 7.2.3.6 where GET requests to `/api/v1/security/posture`, `/api/v1/security/reconciliation`, and `/api/v1/security/reconciliation/summary` returned HTTP 404.

Under strictly enforced safety invariants:
- **Zero financial transactions** were executed.
- **Zero accounts** were debited or credited.
- **Zero beneficiaries** were created, updated, or verified.
- **Zero database migrations or seeders** were re-run; persistent volumes (`postgres-data`, `redis-data`) were strictly preserved.
- Existing execution evidence from Run ID `dc10a375-bdb4-43b7-a07e-5cafd0087a34` was verified intact.
- The `gateway` container was safely rebuilt from current source commit, bringing the running container into 100% alignment with the codebase.
- All SOC endpoints were systematically tested with the analyst identity and verified functional.

---

## 1. Runtime Discrepancy Investigation

### 1.1 Root Cause Analysis
Static inspection and Docker container metadata inspection revealed the root cause of the previous HTTP 404 responses:
- **Container Build Timestamp:** The previously running container `aegis-gateway-1` had image ID `sha256:b9925bbe2f604e13d34b6c75b54fae69f36e4694f84c291f1bbe289a8a8a2b20`, created on **October 28, 2026 at 15:49:29 UTC**.
- **Source Commit History:**
  - `SecurityReconciliationController.java` was committed on **October 29, 2026** (commit `246a064`) and refined on **October 30, 2026** (commit `69fac08`).
  - `SecurityPostureController.java` was committed on **November 1, 2026** (commit `973b310`).
- **Conclusion:** The previous HTTP 404 was **neither an endpoint mapping defect nor an authentication/authorization failure**. The source code in `com.aegis.gateway.posture` and `com.aegis.gateway.reconciliation` was fully implemented, correctly mapped, and properly secured under Spring Security. However, the running container image was built **before** these controllers were authored.
- **Downstream Services Check:** `customer-service`, `account-service`, and `transaction-service` had zero code changes since October 28, 2026, and did not require rebuilding.

---

## 2. Safe Runtime Rebuild & Volume Preservation

### 2.1 Services Rebuilt and Restarted
- **Rebuilt Service:** `gateway` (`infrastructure/docker/compose.yml`)
- **New Deployed Image ID:** `sha256:7cd989396b90ac5debe068f21569ed1bd6482d1b70317dfb08571bb6df4cd054`
- **Build Timestamp:** `2026-11-09T15:30:38Z`
- **Compilation Scope:** 111 Java source files compiled into `gateway-0.1.0-SNAPSHOT.jar` using Eclipse Temurin JDK 25.
- **Container Recreate Command:**
  ```powershell
  docker compose -f infrastructure/docker/compose.yml --env-file config/dev.env up -d --no-deps gateway
  ```
  *(Using `--no-deps` to ensure zero disruption or restarts to postgres, redis, keycloak, or downstream business services).*

### 2.2 Volume & Health Preservation Verification
- All 9 platform containers reported `Up` and `healthy`:
  - `aegis-gateway-1`: `Up (healthy)` on `127.0.0.1:8000`
  - `aegis-customer-service-1`: `Up (healthy)` on `127.0.0.1:8081`
  - `aegis-account-service-1`: `Up (healthy)` on `127.0.0.1:8082`
  - `aegis-transaction-service-1`: `Up (healthy)` on `127.0.0.1:8083`
  - `aegis-postgres-1`: `Up (healthy)` on `127.0.0.1:5433` (`postgres-data` volume preserved)
  - `aegis-redis-1`: `Up (healthy)` on `127.0.0.1:6379` (`redis-data` volume preserved)
  - `aegis-keycloak-1`: `Up (healthy)` on `127.0.0.1:8080`

---

## 3. Systematic SOC Endpoint Integration Results

Every SOC endpoint was verified across three authentication states:
1. **Unauthenticated:** Verified returns **HTTP 401 Unauthorized**.
2. **Customer Identity (`alex.morgan`):** Verified returns **HTTP 403 Forbidden**.
3. **Security Analyst Identity (`analyst`):** Verified returns **HTTP 200 OK** with valid schema.

| Endpoint Name | Method | Path | Analyst Status | Unauth | Customer | Key Response Schema Fields / Verification |
| :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| **Security Overview** | `GET` | `/api/v1/security/overview` | `200 OK` | `401` | `403` | `totalEvents`, `totalAnomalies`, `openIncidents`, `incidentsBySeverity`, `timeSeriesTrend` |
| **Security Events** | `GET` | `/api/v1/security/events` | `200 OK` | `401` | `403` | Paged: `content`, `page`, `size`, `totalElements`, `totalPages`, `hasNext`, `hasPrevious` |
| **Security Incidents** | `GET` | `/api/v1/security/incidents` | `200 OK` | `401` | `403` | Paged: `content`, `page`, `size`, `totalElements`, `totalPages` |
| **Incident Evidence** | `GET` | `/api/v1/security/incidents/{id}/evidence` | `200 OK` | `401` | `403` | Verified on existing incident `ea8781ba-e730-4697-b138-9cb246a5ae5e` |
| **Incident History** | `GET` | `/api/v1/security/incidents/{id}/history` | `200 OK` | `401` | `403` | Verified audit log history for incident |
| **Policy Decisions** | `GET` | `/api/v1/security/policy-decisions` | `200 OK` | `401` | `403` | List of evaluated automated policy decisions |
| **API Discovery** | `GET` | `/api/v1/security/discovery/endpoints` | `200 OK` | `401` | `403` | Paged: `totalObservedEndpoints`, `totalObservedRequests`, `totalMonitoredServices` |
| **Endpoint Intelligence** | `GET` | `/api/v1/security/discovery/endpoints/{id}/intelligence` | `200 OK` | `401` | `403` | Verified on `ep_23af7337833f23a4`: `httpMethod`, `routeTemplate`, `statusDistribution`, `linkedIncidents` |
| **OpenAPI Specifications** | `GET` | `/api/v1/security/specs` | `200 OK` | `401` | `403` | Paged: `totalSpecifications`, `totalOperations` |
| **Security Reconciliation** | `GET` | `/api/v1/security/reconciliation` | `200 OK` | `401` | `403` | Paged: 24 evaluated discrepancy records, `content`, `summary` |
| **Reconciliation Summary** | `GET` | `/api/v1/security/reconciliation/summary` | `200 OK` | `401` | `403` | `matchedCount`, `observedUndocumentedCount`, `coveragePercentage`, `windowHours` |
| **Security Posture** | `GET` | `/api/v1/security/posture` | `200 OK` | `401` | `403` | Paged: 38 assessed endpoints, dimensional breakdown, `confirmedVulnerability=false` |
| **Security Posture Summary** | `GET` | `/api/v1/security/posture/summary` | `200 OK` | `401` | `403` | `totalAssessedEndpoints`: 38, `verifiedDimensionsCount`: 31, `unknownDimensionsCount`: 102 |

---

## 4. Verification of Existing Benign Run Evidence

Evidence from Phase 7.2.3.6 Run `dc10a375-bdb4-43b7-a07e-5cafd0087a34` was audited live:

1. **Correlation IDs Retrievable:** All **15 of 15** original correlation IDs remain stored in Redis / `/api/v1/security/events` and were confirmed queryable by the analyst.
2. **Transaction Record:**
   - Transaction ID `5a9be0d7-b99a-4922-b66b-4a04b40e7d24` status remains `COMPLETED`.
   - Amount: `$25.00 USD`.
   - Database reference: `2720bdd4-a41b-42f9-b928-f81ff5aa04ce` (idempotency key).
3. **Source Account Balance:**
   - Alex Morgan's account `20000000-0000-4000-8000-000000000001` available balance remains **`$12,358.74 USD`** (no duplicate debits).
4. **Destination Account Balance:**
   - Sam Taylor's account `20000000-0000-4000-8000-000000000003` available balance remains **`£5,300.25 GBP`** (untouched).
5. **Beneficiary Status:**
   - Sam Taylor's beneficiary record `6a4484af-8496-4bb7-b3b0-e49ee5e8efec` remains `VERIFIED`.
6. **Ledger Uniqueness Invariants:**
   - `SELECT count(*) FROM transaction_data.transactions WHERE reference = '2720bdd4-a41b-42f9-b928-f81ff5aa04ce'` = **1**.
   - `SELECT count(*) FROM account_data.account_debits WHERE reference = '2720bdd4-a41b-42f9-b928-f81ff5aa04ce'` = **1**.
   - **Zero duplicate entries** exist.

---

## 5. Reconciliation & Posture Invariants

- **Reconciliation:** Observed 24 evaluated discrepancies across 24h window; accurately identifies observed wire traffic without schema conflicts.
- **Posture Assessments:**
  - 38 endpoints assessed across all microservice boundaries.
  - **Unknown Evidence Invariant:** 102 dimensions are accurately scored as `UNKNOWN` due to absence of specific security tests rather than being falsely classified as secure.
  - **Zero False Vulnerabilities:** `confirmedVulnerability == false` on all 38 endpoints.
  - Normal customer and inquiry traffic from `SCEN-BENIGN-01` is not misrepresented as vulnerability findings.

---

## 6. Automated Test Suite Results

| Test Suite | Scope | Tests Run | Result | Notes |
| :--- | :--- | :---: | :---: | :--- |
| **Backend Gateway Unit/Integration** | `mvn test` (Posture & Reconciliation) | 21 | **21/21 PASS** | Controller & service contracts verified |
| **Frontend Angular SOC Dashboard** | `ng test --watch=false` | 169 | **169/169 PASS** | Full component & service suite |
| **Frontend Production Build** | `ng build` | — | **SUCCESS** | 0 errors, 0 warnings (bundle: 374.8 kB) |
| **Python Simulation Framework** | `pytest simulation/tests` | 67 | **67/67 PASS** | Added multi-page posture pagination test |

---

## 7. Outstanding Limitations & Readiness Classification

### Outstanding Limitations
1. **Container Alignment Procedure:** Any subsequent modifications to Gateway source code must be followed by `docker compose build gateway` and `docker compose up -d --no-deps gateway` before live testbed testing.
2. **Reconciliation Coverage:** Coverage percentage currently stands at 0% until OpenAPI specifications are formally ingested and linked to discovered runtime routes via `/api/v1/security/specs`.

### Final Status Decision
**`READY_FOR_DATA_LEAKAGE_SIMULATION`**

All backend services, SOC endpoints, and simulation frameworks are fully aligned with source code, healthy, verified, and prepared for Phase 7.2.4 data leakage attack scenarios.

---
*Report certified by Aegis FinTech & Security Engineering.*
