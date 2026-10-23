# Aegis Pre-Phase 4 Hardening Plan & Execution Report

**Date:** October 23, 2026  
**Auditor / Engineer:** Antigravity Advanced Agentic Coding  
**Baseline Git Commit:** `0cd6754de1edb328edf594733a3c9a628cf92c46`  
**Branch:** `main`  
**Status:** **COMPLETED** — All 7 Increments Fully Remediated & Verified

---

## 1. Baseline Environment & Toolchain

- **JDK:** OpenJDK 25.0.1 LTS (Oracle Corporation / Eclipse Temurin)
- **Build System:** Apache Maven 3.9.16
- **Frameworks:** Spring Boot 3.5.6, Spring Cloud 2025.0.0 (Spring Cloud Gateway Server WebMvc)
- **Container Engine:** Docker Engine 29.8.0, Docker Compose v2.41.0
- **Live Container Fleet (9/9 Running & Healthy):**
  - `aegis-gateway-1` (port 8000)
  - `aegis-customer-service-1` (port 8081)
  - `aegis-account-service-1` (port 8082)
  - `aegis-transaction-service-1` (port 8083)
  - `aegis-postgres-1` (port 5433)
  - `aegis-redis-1` (port 6379)
  - `aegis-keycloak-1` (port 8080, 9000)
  - `aegis-prometheus-1` (port 9090)
  - `aegis-grafana-1` (port 3000)
- **Automated Test Count:** **103 automated tests** (0 failures, 0 errors, 0 skipped):
  - `gateway`: 32 tests (expanded from 21 baseline tests)
  - `customer-service`: 17 tests
  - `account-service`: 26 tests
  - `transaction-service`: 28 tests

---

## 2. Audit Findings & Verification Against Source Code

### Finding 1: Analyst Access Surrogate Check (CONFIRMED)
- **Verification Evidence:** In `scripts/verify-phase3-gate.ps1` lines 89–95 of commit `0cd6754`, the test labeled `Analyst Role Access Verification` invoked `GET http://127.0.0.1:8000/actuator/health` with analyst headers and asserted `$secRes.status -eq "UP"`.
- **Verdict:** Confirmed. `/actuator/health` is configured as `.permitAll()` in [SecurityConfig.java](file:///c:/Users/nikhi/aegis/gateway/src/main/java/com/aegis/gateway/security/SecurityConfig.java). It proved only that the container was running, not that `ROLE_SECURITY_ANALYST` was authorized to access security audit telemetry.
- **Remediation:** Implemented genuine `GET /api/v1/security/events` backed by PostgreSQL persistence and enforced server-side RBAC.

### Finding 2: Concurrency Benchmark Reality (CONFIRMED)
- **Verification Evidence:** In `scripts/verify-phase3-gate.ps1` lines 220–244 of commit `0cd6754`, the test loop was `for ($i = 0; $i -lt 50; $i++)` running sequentially on a single thread.
- **Verdict:** Confirmed. Actual concurrency was $c = 1$. The claim of "50 concurrent requests" did not reflect concurrent load.
- **Remediation:** Built `scripts/load-test.ps1` utilizing asynchronous parallel `System.Net.Http.HttpClient` tasks with $c = 10$, separate warm-up cycles, wall-clock timing, throughput (RPS), and latency percentiles (p50/p95/p99).

### Finding 3: Telemetry Schema Discrepancy (CONFIRMED)
- **Verification Evidence:** `docs/phase-3.md` documented columns `event_id`, `client_ip`, `route_template`, `request_uri`, `user_id`, `request_payload_hash`, `response_size_bytes`.
- **Actual Active Schema (`V1__security_schema.sql`):**
  - Table: `security_data.api_events`
  - Columns: `id` (UUID), `correlation_id` (VARCHAR(64)), `timestamp` (TIMESTAMPTZ), `source_ip` (VARCHAR(45)), `http_method` (VARCHAR(10)), `request_path` (VARCHAR(512)), `route_id` (VARCHAR(64)), `status_code` (INT), `latency_ms` (BIGINT), `auth_subject` (VARCHAR(128)), `auth_roles` (VARCHAR(256)), `customer_id` (VARCHAR(64)), `user_agent` (VARCHAR(256)), `payload_hash` (CHAR(64)), `anomaly_flags` (VARCHAR(128) DEFAULT 'NONE').
  - Note: `response_size_bytes` was never in the schema and not stored.
- **Remediation:** Reconciled documentation in `docs/phase-3.md` to reflect active schema and documented the DTO projection mapping.

### Finding 4: Observability Infrastructure Gap (CONFIRMED)
- **Verification Evidence:** `spring-boot-starter-actuator` was present, but `micrometer-registry-prometheus` was absent from all POMs. No Prometheus scraper or Grafana dashboard existed.
- **Remediation:** Added `micrometer-registry-prometheus` across all 4 services, exposed `/actuator/prometheus`, added low-cardinality security metrics, and provisioned Prometheus (`:9090`) and Grafana (`:3000`).

### Finding 5: Direct Host Port Exposure (CONFIRMED)
- **Verification Evidence:** `compose.yml` exposed backend service ports `127.0.0.1:8081`, `8082`, `8083`.
- **Remediation:** Created `infrastructure/docker/compose.hardened.yml` using `ports: !reset []` to drop host port publication for backend services in hardened deployments while retaining internal network routing.

---

## 3. Architecture & Boundary Decision: `GET /api/v1/security/events`

### Module Decision: Implemented in `gateway`
- **Ownership & Boundary Justification:**
  - `gateway` already owns the `security_data` Flyway migrations, PostgreSQL connection pool, and `ApiEventRepository`.
  - Telemetry is drained from Redis Stream directly into `security_data.api_events` by `gateway`'s `TelemetryDrainWorker`.
  - Creating a separate security service solely for reading these events would introduce unnecessary network hops, duplicate datasource credentials, and architectural bloat. Exposing the read API from `gateway` preserves single ownership of the `security_data` schema.
- **API Specification:**
  - Route: `GET /api/v1/security/events` (and `GET /security/events`)
  - Server-Side RBAC: `@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")`
  - Unauthorized Principal: HTTP 401 Unauthorized (via standard OAuth2 resource server)
  - Forbidden Role (`CUSTOMER`): HTTP 403 Forbidden
  - Deterministic Ordering: `ORDER BY timestamp DESC, id DESC`
  - Bounded Pagination: `page >= 0`, `size` clamped to $[1, 100]$ (default 20)
  - Filtering: Optional `statusCode` and `httpMethod`
  - Projection DTO: [SecurityEventResponse.java](file:///c:/Users/nikhi/aegis/gateway/src/main/java/com/aegis/gateway/telemetry/SecurityEventResponse.java) surfaces `id`, `correlationId`, `timestamp`, `sourceIp`, `httpMethod`, `requestPath`, `routeId`, `statusCode`, `latencyMs`, `authSubject`, `authRoles`, `customerId`, `anomalyFlags`. Omits raw payloads, credentials, and internal table structures.
  - Failure Resilience: Returns HTTP 503 Service Unavailable when the database is unreachable, with ProblemDetail payload.

---

## 4. Execution Evidence Across Increments

### Increment 2 — Real Security-Event API Tests (10/10 Passed)
Automated test suite in [SecurityEventControllerTest.java](file:///c:/Users/nikhi/aegis/gateway/src/test/java/com/aegis/gateway/telemetry/SecurityEventControllerTest.java):
1. `unauthenticatedRequestReturnsUnauthorized()`: [PASS] HTTP 401
2. `customerRoleReturnsForbidden()`: [PASS] HTTP 403
3. `securityAnalystRoleReturnsEventsPage()`: [PASS] HTTP 200 with JSON page
4. `securityAdminRoleReturnsEventsPage()`: [PASS] HTTP 200 with JSON page
5. `actualPersistedEventReturnedWithCorrectFields()`: [PASS] Validated all DTO fields
6. `emptyResultReturnsEmptyPage()`: [PASS] Total 0, empty list
7. `paginationBoundariesAndDeterministicOrdering()`: [PASS] Page slicing & descending sort
8. `authorizationBypassAttemptsFail()`: [PASS] Role headers / query params cannot elevate privilege
9. `filteredQueriesByStatusCodeAndMethod()`: [PASS] Deterministic filter matching
10. `databaseUnavailableReturnsServiceUnavailable()`: [PASS] HTTP 503 ProblemDetail

### Increment 3 — Live Verification Gate (20/20 Checks Passed)
Executed `scripts/verify-phase3-gate.ps1`:
```
=================================================================
    AEGIS PHASE 3 VERIFICATION & SECURITY HARDENING GATE        
=================================================================

--- 1. ACQUIRING TOKENS FROM REAL KEYCLOAK ---
[PASS] Keycloak Token Acquisition - Tokens acquired for CUSTOMER, SECURITY_ANALYST, and SECURITY_ADMIN

--- 2. AUTHENTICATION & ROLE-BASED ACCESS CONTROL ---
[PASS] Missing Bearer Token - Rejected with HTTP 401 Unauthorized
[PASS] Malformed JWT - Rejected with HTTP 401 Unauthorized
[PASS] Forged JWT Signature - Rejected with HTTP 401 Unauthorized
[PASS] Valid Customer Token Access - Customer retrieved: Alex Morgan
[PASS] Customer Role Restriction on Security Endpoints - Rejected with HTTP 403 Forbidden
[PASS] Analyst Role Access Verification - Analyst retrieved real telemetry events: 349 total events (page size: 10)

--- 3. OBJECT-LEVEL AUTHORIZATION (BOLA / IDOR DEFENSE) ---
[PASS] BOLA Defense: Customer Profile - Properly rejected with HTTP 403 Forbidden
[PASS] BOLA Defense: Account Balance - Properly rejected with HTTP 403 Forbidden
[PASS] BOLA Defense: Cross-Customer Query Parameter - Properly rejected with HTTP 403 Forbidden
[PASS] BOLA Defense: Unfiltered Accounts Auto-Scoping - Returned 2 accounts, all owned by Alex Morgan (no cross-customer leaks)
[PASS] Admin Audit Read Privilege - Admin authorized to view customer for audit: Sam

--- 4. GATEWAY-BYPASS DEFENSE & HMAC PROTOCOL VERIFICATION ---
[PASS] Bypass Defense: Missing Signature Header - Rejected with HTTP 403 Forbidden
[PASS] Bypass Defense: Invalid Signature Header - Rejected with HTTP 403 Forbidden
[PASS] Correlation ID Propagation - X-Correlation-Id echoed in response: phase3-cid-verify-1515357035

--- 5. TELEMETRY DURABILITY & PRIVACY AUDIT ---
[PASS] Telemetry Stream-to-PostgreSQL Persistence - Persisted event for correlation ID phase3-cid-verify-1515357035 (Route: /customers/{id})
[PASS] Telemetry Privacy: Unverified Spoof Defense - Unauthenticated request recorded subject as 'anonymous' with status 401

--- 6. TRANSFER ORCHESTRATION & IDEMPOTENCY ---
[PASS] Transfer Execution - Transfer completed: ID 743b3bd4-3997-442b-b77d-ec5ceba0b306, Reference: e2e-idem-phase3-2078121719
[PASS] Transfer Idempotency - Re-sent transfer returned exact same ID without duplicating transaction

--- 7. CONCURRENCY & PERFORMANCE BENCHMARK (50 REQUESTS, CONCURRENCY = 10) ---
[PASS] Concurrency & Latency Benchmark - 50 requests (c=10): 0 errors (0.0%). Duration: 270.3ms, Throughput: 185 RPS. Median (p50): 31.7ms, p95: 91.1ms, p99: 92.1ms

=================================================================
GATE VERIFICATION SUMMARY: 20 / 20 TESTS PASSED
=================================================================
```

### Increment 4 — Schema Reconciliation
- Reconciled [docs/phase-3.md](file:///c:/Users/nikhi/aegis/docs/phase-3.md) to match [V1__security_schema.sql](file:///c:/Users/nikhi/aegis/gateway/src/main/resources/db/migration/V1__security_schema.sql).
- Added explicit DTO mapping table clarifying differences between database storage and external API representation.

### Increment 5 — Observability Evidence
- **Prometheus Scrape Endpoint:** Verified `http://127.0.0.1:8000/actuator/prometheus` and backend service scrape endpoints.
- **Active Scrape Targets (`http://127.0.0.1:9090/api/v1/targets`):**
  - `http://gateway:8000/actuator/prometheus`: `UP` (0 errors)
  - `http://customer-service:8081/actuator/prometheus`: `UP` (0 errors)
  - `http://account-service:8082/actuator/prometheus`: `UP` (0 errors)
  - `http://transaction-service:8083/actuator/prometheus`: `UP` (0 errors)
- **Live Prometheus Metric Retrieval:**
  - `aegis_telemetry_events_total`: 329 requests for `/api/v1/customers/{id}` (status 200), 12 (status 401), 3 (status 403), 3 for `/api/v1/security/events` (status 200), 6 for `/api/v1/transfers` (status 201).
  - `aegis_trust_rejections_total`: `reason="invalid_signature"`: 9 on `customer-service`, 6 on `transaction-service`; `reason="missing_token"`: 3 on `customer-service`.
- **Grafana Provisioning (`http://127.0.0.1:3000`):**
  - Datasource `Prometheus` (`http://prometheus:9090`) default and healthy.
  - Dashboard `Aegis Security & Telemetry Overview` (UID `aegis-overview`) loaded with panels for HTTP throughput, latency percentiles, telemetry queue lag, and security violations.

### Increment 6 — Reproducible Concurrent Load Test
Executed `scripts/load-test.ps1 -Concurrency 10 -TotalRequests 100 -WarmupRequests 20`:
```
Test Environment:
  Host OS:             Microsoft Windows 11 Home Single Language
  CPU Cores:           12 logical cores
  RAM:                 15.66 GB
  Target Gateway:      http://127.0.0.1:8000
  Concurrency Level:   10 concurrent workers
  Total Requests:      100
  Warmup Iterations:   20

Benchmark Results:
  Total Requests:       100
  Successful (200 OK):  100 (100.0%)
  Failures / Dropped:   0
  Total Duration:       472 ms (0.47 s)
  Throughput:           211.86 requests/sec
  Latency Mean:         39.37 ms
  Latency Median (p50): 30.24 ms
  Latency p95:          79.75 ms
  Latency p99:          115.11 ms
```
*Note: Results establish local gateway and service pipeline performance; they do not represent production capacity under unconstrained horizontal scale.*

### Increment 7 — Network Boundary Hardening
- Created [infrastructure/docker/compose.hardened.yml](file:///c:/Users/nikhi/aegis/infrastructure/docker/compose.hardened.yml) using Docker Compose `ports: !reset []` syntax.
- Validated via `docker compose -f infrastructure/docker/compose.yml -f infrastructure/docker/compose.hardened.yml config`:
  - `customer-service`: No host ports published. Reachable only via internal Docker bridge.
  - `account-service`: No host ports published. Reachable only via internal Docker bridge.
  - `transaction-service`: No host ports published. Reachable only via internal Docker bridge.
  - `gateway`: Published to `127.0.0.1:8000`.
  - `keycloak`: Published to `127.0.0.1:8080`.
  - `prometheus`: Published to `127.0.0.1:9090`.
  - `grafana`: Published to `127.0.0.1:3000`.

---

## 5. Final Verification Summary Matrix

| Gate / Component | Baseline (`0cd6754`) | Pre-Phase 4 Hardening | Status |
| :--- | :--- | :--- | :--- |
| **Total Automated Tests** | 92 tests | **103 tests** (0 fail, 0 skip) | **PASS** |
| **Security Events API** | Not implemented (surrogate `/health`) | `GET /api/v1/security/events` with RBAC | **PASS** |
| **Live Gate Checks** | 20 checks (1 surrogate, sequential) | 20 checks (real event API, true concurrent) | **PASS** |
| **Telemetry Schema** | Discrepant in `phase-3.md` | Fully reconciled to `V1__security_schema.sql` | **PASS** |
| **Observability Stack** | Actuator only (no Prometheus) | Prometheus + Grafana + custom metrics | **PASS** |
| **Concurrent Benchmark** | Sequential loop ($c=1$) | Native async HttpClient ($c=10, 211.86$ RPS) | **PASS** |
| **Network Segmentation** | Backend ports open to host | `compose.hardened.yml` (`!reset []`) | **PASS** |
