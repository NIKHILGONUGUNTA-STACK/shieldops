# Aegis Phase 7.2.3.2 — Live Testbed Bring-up & Controlled Integration Readiness

**Document Version:** 1.0.0  
**Status:** Audit & Readiness Verification Complete (Authorization Gate Intact)  
**Date:** 2026-11-06  
**Scenario ID:** `SCEN-BENIGN-01`  
**Vector Category:** `BENIGN`  
**Test Suite:** `simulation/tests/test_benign_customer_flow.py` (46 passing Python unit tests total)

---

## 1. Executive Summary & Objective

Phase 7.2.3.2 conducts the formal environment inspection, configuration validation, dry-run preflight, and financial safety review required prior to executing live transactions through the Aegis Gateway.

In strict compliance with authorization boundaries:
- **No live mutations performed:** Zero financial transfers, account debits, or beneficiary records were created on live storage during this step.
- **Controlled Integration Gate:** The live execution command (`--execute`) is explicitly held at the authorization boundary.
- **Zero Secret Commits:** No passwords, access tokens, client secrets, or private environment files are committed to version control.
- **Database Volumes Preserved:** No database volumes (`postgres-data`, `redis-data`) were reset or deleted.

---

## 2. Local Environment & Infrastructure Inspection

### 2.1 Docker Compose Services Topology (`infrastructure/docker/compose.yml`)

The platform architecture defines 9 containerized services orchestrated via Docker Compose:

| Container Name | Service Role | Image | Local Port | Health Check Probe |
| :--- | :--- | :--- | :--- | :--- |
| `postgres` | Central PostgreSQL 17 | `postgres:17-alpine` | `127.0.0.1:5433` | `pg_isready -U aegis_owner -d aegis` |
| `redis` | Redis 7 Stream & Sliding Window | `redis:7-alpine` | `127.0.0.1:6379` | `redis-cli ping` |
| `keycloak` | Keycloak 26 Identity Provider | `quay.io/keycloak/keycloak:26.4.2` | `127.0.0.1:8080`, `9000` | Port 9000 TCP probe |
| `customer-service` | Customer Microservice | `services/Dockerfile` | `127.0.0.1:8081` | `/actuator/health/readiness` |
| `account-service` | Account Microservice | `services/Dockerfile` | `127.0.0.1:8082` | `/actuator/health/readiness` |
| `transaction-service` | Transaction Microservice | `services/Dockerfile` | `127.0.0.1:8083` | `/actuator/health/readiness` |
| `gateway` | Aegis Security Gateway & SOC | `gateway/Dockerfile` | `127.0.0.1:8000` | `/actuator/health/readiness` |
| `prometheus` | Prometheus 2.54 Metrics | `prom/prometheus:v2.54.1` | `127.0.0.1:9090` | `/-/healthy` |
| `grafana` | Grafana 11.2 Dashboard | `grafana/grafana:11.2.0` | `127.0.0.1:3000` | `/api/health` |

### 2.2 Database Volumes & Seed Data Inventory

Persistent data resides across isolated PostgreSQL schemas provisioned through Flyway migrations:

1. **Customer Schema (`customer_data` - Flyway V1 & V2):**
   - Alex Morgan: `10000000-0000-4000-8000-000000000001` (`CUST-10001`, `alex.morgan@example.test`, status: `ACTIVE`, US).
   - Sam Taylor: `10000000-0000-4000-8000-000000000002` (`CUST-10002`, `sam.taylor@example.test`, status: `ACTIVE`, GB).
   - Jordan Lee: `10000000-0000-4000-8000-000000000003` (`CUST-10003`, `jordan.lee@example.test`, status: `SUSPENDED`, CA).

2. **Account Schema (`account_data` - Flyway V1 & V2):**
   - Alex Morgan USD Account 1: `20000000-0000-4000-8000-000000000001` (`ACCT-00010001`, USD, balance: `$12,500.00`, status: `ACTIVE`).
   - Alex Morgan USD Account 2: `20000000-0000-4000-8000-000000000002` (`ACCT-00010002`, USD, balance: `$875.50`, status: `ACTIVE`).
   - Sam Taylor GBP Account: `20000000-0000-4000-8000-000000000003` (`ACCT-00020001`, GBP, balance: `£5,300.25`, status: `ACTIVE`).

3. **Transaction Schema (`transaction_data` - Flyway V1):**
   - Tables: `beneficiaries` (`id`, `customer_id`, `name`, `destination_account_reference`, `currency`, `status`).
   - Tables: `transactions` (`id`, `reference`, `customer_id`, `source_account_id`, `beneficiary_id`, `amount`, `currency`, `status`).

4. **Gateway Security Schema (`security_data` - Flyway V1–V6):**
   - Tables: `api_events`, `security_incidents`, `security_evidence`, `api_endpoints`, `api_specifications`, `api_spec_operations`, `api_posture_findings`.

### 2.3 Keycloak Realm Initialization (`keycloak/realm/aegis-dev-realm.json`)

The `aegis-dev` realm defines the authentication parameters:
- **Public Client:** `aegis-local` with Direct Access Grants (`grant_type=password`) enabled.
- **Protocol Mappers:** User attribute mappers for `customerId` and `customerNumber` embedded directly into the access token JWT claims.
- **Identities:** Pre-configured accounts for `alex.morgan` (`CUSTOMER`), `sam.taylor` (`CUSTOMER`), `analyst` (`SECURITY_ANALYST`), and `admin` (`SECURITY_ADMIN`).

### 2.4 Redis & Telemetry Stream Engine

- Redis 7 manages the telemetry event ingestion stream (`aegis:stream:api-events`) with a consumer group processed asynchronously by `DetectionStreamConsumer`.
- Telemetry events persist to `security_data.api_events` for SOC reconciliation and threat correlation.

---

## 3. Configuration & Local Isolation Validation

Executing `python -m simulation.cli config validate` verifies the defensive configuration rules:

```
                        Aegis Simulation Configuration                         
┌────────────────────────┬────────────────────────────┬───────────────────────┐
│ Component              │ Property                   │ Configured Value      │
├────────────────────────┼────────────────────────────┼───────────────────────┤
│ Gateway                │ Base URL                   │ http://localhost:8000 │
│ Gateway                │ Timeout (seconds)          │ 10.0                  │
│ Gateway                │ Max Retries                │ 2                     │
│ Gateway                │ Allow Synthetic Source IP  │ False                 │
│ Keycloak               │ Base URL                   │ http://localhost:8080 │
│ Keycloak               │ Realm                      │ aegis-dev             │
│ Keycloak               │ Client ID                  │ aegis-local           │
│ Keycloak               │ Token Expiry Buffer (s)    │ 30                    │
│ Downstream Health      │ Customer Service URL       │ http://localhost:8081 │
│ Downstream Health      │ Account Service URL        │ http://localhost:8082 │
│ Downstream Health      │ Transaction Service URL    │ http://localhost:8083 │
│ Execution              │ Environment ID             │ local-dev             │
│ Execution              │ Allow Non-Local Override   │ False                 │
│ Execution              │ Max Concurrency            │ 5                     │
│ Security Context       │ Configured User            │ 3 identity secret(s)  │
│                        │ Credentials                │ loaded                │
└────────────────────────┴────────────────────────────┴───────────────────────┘
[OK] Configuration is valid and strictly enforces local-only isolation safeguards.
```

### Safety Confirmations:
1. **Localhost Isolation:** All target hosts strictly resolve to `localhost` (`127.0.0.1`). Any non-local URL triggers a hard safety violation.
2. **Gateway Route Enforcement:** All simulation business traffic is routed to port `8000`. Direct requests to microservice ports (8081, 8082, 8083) are prohibited except for diagnostic probes via `doctor`.
3. **Explicit Credentials:** No hardcoded fallback passwords exist in application code. Credentials are read from local environment variables or `.env` (which is excluded from Git via `.gitignore`).
4. **Zero Secret Leakage:** Access tokens, client secrets, and passwords are fully masked in logs and reports.

---

## 4. Live Service Probes & Preflight Diagnostics

Executing `python -m simulation.cli doctor`:

```
                    Aegis Testbed Diagnostic Health Matrix                     
┌──────────────────┬──────────────────────────────────────┬────────┬──────────┐
│ Service          │ Probe Target                         │ Status │  Latency │
├──────────────────┼──────────────────────────────────────┼────────┼──────────┤
│ Aegis Gateway    │ http://localhost:8000/actuator/read… │ [FAIL] │  2453 ms │
│ Keycloak IdP     │ http://localhost:8080/realms/aegis…  │ [FAIL] │  2332 ms │
│ Customer Service │ http://localhost:8081/actuator/read… │ [FAIL] │  2331 ms │
│ Account Service  │ http://localhost:8082/actuator/read… │ [FAIL] │  2330 ms │
│ Transaction      │ http://localhost:8083/actuator/read… │ [FAIL] │  2327 ms │
└──────────────────┴──────────────────────────────────────┴────────┴──────────┘
[WARN] Some testbed services are unreachable. Ensure containers are running with 'docker compose up -d'.
```

### Dry-Run Execution Attempt:
Executing `python -m simulation.cli run --scenario SCEN-BENIGN-01 --dry-run`:
- **Result:** Stopped safely at Step 0.
- **Diagnostic:** `AuthenticationError: Keycloak connection error during token acquisition for 'alex.morgan': All connection attempts failed`.
- **Safety Invariant Maintained:** Zero HTTP requests were dispatched to downstream services. Zero records were modified.

---

## 5. Financial Safety Review

Prior to live execution, all financial safety invariants were verified:

| Invariant Check | Required Specification | Seed/Design Verification | Status |
| :--- | :--- | :--- | :--- |
| **Account Ownership** | Account belongs to Alex Morgan (`1000...0001`) | Seed account `2000...0001` owned by customer `1000...0001` | **VERIFIED** |
| **Account Status** | Status equals `ACTIVE` | Seed account `2000...0001` status is `ACTIVE` | **VERIFIED** |
| **Currency Alignment** | Currency equals `USD` | Seed account `2000...0001` currency is `USD` | **VERIFIED** |
| **Balance Sufficiency** | Available balance $\ge \$25.00$ | Seed account balance is `$12,500.00` | **VERIFIED** |
| **Beneficiary Reference** | Destination matches `ACCT-00020001` | Sam Taylor's seed account reference is `ACCT-00020001` | **VERIFIED** |
| **Transfer Amount** | Bounded amount ($\le \$1000.00$) | Configured transfer amount is `$25.00` | **VERIFIED** |
| **Idempotency Key** | Unique per transfer attempt | Generated via UUIDv4 (`Idempotency-Key` header) | **VERIFIED** |
| **Uncertain Result Handling** | No blind automatic retries | POST retries disabled; idempotent replay supported | **VERIFIED** |
| **Arithmetic Precision** | Exact balance decrement | `Decimal('12500.00') - Decimal('25.00') = Decimal('12475.00')` | **VERIFIED** |

---

## 6. Live Execution Authorization Boundary

### Command for Live Execution (Deferred):
```powershell
python -m simulation.cli run --scenario SCEN-BENIGN-01 --execute
```

### Exact Planned Mutations:
1. `CREATE_BENEFICIARY` (if not already verified):
   - `customerId`: `10000000-0000-4000-8000-000000000001`
   - `name`: `Sam Taylor`
   - `destinationAccountReference`: `ACCT-00020001`
   - `currency`: `USD`
2. `VERIFY_BENEFICIARY`:
   - `destinationAccountReference`: `ACCT-00020001`
   - Assert `status == "VERIFIED"`
3. `EXECUTE_TRANSFER`:
   - `sourceAccountId`: `20000000-0000-4000-8000-000000000001`
   - `amount`: `$25.00 USD`
   - Expected balance transition: `$12,500.00 -> $12,475.00 USD`
   - Assert transaction `status == "COMPLETED"`

### Remaining Blocker:
- The Docker Desktop engine (`npipe:////./pipe/dockerDesktopLinuxEngine`) is currently stopped on the host OS.
- To execute live traffic, the developer must start Docker Desktop and bring up the container stack:
  ```powershell
  docker compose -f infrastructure/docker/compose.yml --env-file config/dev.env up -d
  ```
- All code, configuration, models, and safety invariants are 100% prepared and verified offline.

---

## 7. Status Distinction: Mocked vs. Live

- **Mocked Verification Status:** **100% SUCCESS** (46 Python unit tests passing, 4 backend platform contract baseline tests passing).
- **Live Integration Status:** **AWAITING DOCKER ENGINE BRING-UP** (Configuration validated, safety invariants locked, execution gated behind authorization boundary).
