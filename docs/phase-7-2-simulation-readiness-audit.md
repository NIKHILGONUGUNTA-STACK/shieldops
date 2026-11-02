# Aegis Phase 7.2 Preparation: Simulation Environment & Data Readiness Audit

## 1. Executive Summary & Audit Scope

This document provides a comprehensive readiness audit of the Aegis platform in preparation for **Phase 7.2: Realistic Local FinTech Simulation Environment**. 

The goal of Phase 7.2 is to build a repeatable, automated local simulation harness that generates authentic HTTP traffic through the Aegis API Gateway (`http://localhost:8000`), exercising both legitimate banking customer workflows and adversarial attack scenarios.

### Scope of the Audit
- **FinTech Microservices**: Customer Service (`:8081`), Account Service (`:8082`), Transaction Service (`:8083`).
- **Identity & Authentication**: Keycloak 26 (`:8080`), `aegis-dev` realm, OIDC token acquisition, JWT claims, and Spring Security principal extraction.
- **Gateway & Telemetry**: Spring Cloud Gateway routing, `CorrelationFilter`, `TelemetryFilter`, `InternalTrustAttestationFilter`, Redis Streams (`aegis:stream:api-events`), and PostgreSQL `security_data.api_events`.
- **Detection & Security Controls**: `ThreatDetectionEngine`, six active detection rules (`RULE-BOLA-01`, `RULE-AUTH-01`, `RULE-RATE-01`, `RULE-PROBE-01`, `RULE-INJ-01`, `RULE-DATA-01`), correlation correlators, incident management, and Phase 7.1 Security Posture Assessment.
- **Data Readiness & Simulation Architecture**: Assessment of seed data, customer isolation, schema constraints, and design of the upcoming `simulation/` module.

> [!NOTE]
> **Audit Invariant Compliance**: This audit is strictly non-destructive. No source code, database schemas, configuration files, or runtime states were modified during this inspection. All credentials, tokens, and secrets have been redacted.

---

## 2. Existing FinTech Microservices Inspection

### 2.1 Microservice Overview & Port Allocation
| Service | Internal Port | Gateway Route Prefix | Database Schema | Primary Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| **`customer-service`** | `8081` | `/api/v1/customers/**`<br>`/customers/**` | `customer_data` | Customer entity view and detailed profile retrieval |
| **`account-service`** | `8082` | `/api/v1/accounts/**`<br>`/accounts/**` | `account_data` | Account lookup, balance checks, and balance debits |
| **`transaction-service`** | `8083` | `/api/v1/beneficiaries/**`<br>`/api/v1/transactions/**`<br>`/api/v1/transfers/**` | `transaction_data` | Beneficiary registration & verification, transfer execution, ledger audit |

---

### 2.2 Endpoint Inventory & Contract Specification

#### A. Customer Service (`customer-service`)
- **`GET /customers/{id}`**
  - **Description**: Retrieves basic customer identity and lifecycle status.
  - **Query Parameters**: None.
  - **Headers Evaluated**: `X-Customer-Id`, `X-Roles`.
  - **Response (200 OK)**:
    ```json
    {
      "id": "10000000-0000-4000-8000-000000000001",
      "customerNumber": "CUST-10001",
      "firstName": "Alex",
      "lastName": "Morgan",
      "status": "ACTIVE",
      "createdDate": "2024-01-15"
    }
    ```
  - **Authorization**: Enforced via `checkCustomerAccess()`. If caller customer UUID != target resource UUID, returns `403 Forbidden` (`"Access to another customer's resources is forbidden"`). Bypassed only if caller holds `ROLE_SECURITY_ADMIN` or `ROLE_SECURITY_ANALYST`.
  - **Error Outcomes**: `404 Not Found` (`"Customer not found"`), `403 Forbidden` (BOLA/Cross-customer), `400 Bad Request` (Malformed UUID).

- **`GET /customers/{id}/profile`**
  - **Description**: Retrieves sensitive profile data including email and country code.
  - **Response (200 OK)**:
    ```json
    {
      "id": "10000000-0000-4000-8000-000000000001",
      "customerNumber": "CUST-10001",
      "firstName": "Alex",
      "lastName": "Morgan",
      "email": "alex.morgan@example.test",
      "countryCode": "US",
      "status": "ACTIVE"
    }
    ```
  - **Authorization**: Identical ownership validation as `GET /customers/{id}`.

> [!WARNING]
> **Customer Write Operations**: Customer Service has **no** `POST`, `PUT`, `PATCH`, or `DELETE` endpoints. All customer records are read-only and sourced from database migrations.

---

#### B. Account Service (`account-service`)
- **`GET /accounts`**
  - **Description**: Lists accounts.
  - **Query Parameters**: `customerId` (optional UUID).
  - **Authorization**: If caller is a customer, `customerId` is forcibly scoped to `callerUuid`. Attempting to query `?customerId=<other-uuid>` returns `403 Forbidden`. If no parameter is passed, returns only accounts owned by caller. Privileged analysts can view all accounts.
  - **Response (200 OK)**: Array of `AccountView`.

- **`GET /accounts/{id}`**
  - **Description**: Retrieves detailed account info with an embedded call to Customer Service (`/customers/{customerId}/profile`) via `CustomerClient`.
  - **Response (200 OK)**:
    ```json
    {
      "id": "20000000-0000-4000-8000-000000000001",
      "accountNumber": "ACCT-00010001",
      "customerId": "10000000-0000-4000-8000-000000000001",
      "currency": "USD",
      "balance": 12500.0000,
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
  - **Authorization**: Enforced via `checkAccountOwnership()`. If `account.getCustomerId() != callerUuid`, returns `403 Forbidden`.
  - **Downstream Dependency**: If Customer Service is down, returns `502 Bad Gateway` (`"Customer service unavailable"`).

- **`GET /accounts/{id}/balance`**
  - **Description**: Lightweight balance check without external client round-trips.
  - **Response (200 OK)**:
    ```json
    {
      "accountId": "20000000-0000-4000-8000-000000000001",
      "currency": "USD",
      "availableBalance": 12500.0000,
      "status": "ACTIVE"
    }
    ```

- **`POST /accounts/{id}/debits`**
  - **Description**: Internal debit endpoint used during transfer processing.
  - **Request Body (`DebitRequest`)**:
    ```json
    {
      "reference": "TXN-REF-1001",
      "amount": 250.0000,
      "currency": "USD"
    }
    ```
  - **Validation Rules**: `@NotBlank @Size(max=80) reference`, `@DecimalMin("0.0001") @Digits(15, 4) amount`, `@Pattern(regexp="[A-Z]{3}") currency`.
  - **Business Rules**: Fails with `409 Conflict` if account status != `ACTIVE` or balance < amount. Inserts immutable record into `account_data.account_debits`.

---

#### C. Transaction Service (`transaction-service`)
- **`GET /beneficiaries`**
  - **Description**: Lists registered transfer recipients for a customer.
  - **Query Parameters**: `customerId` (optional). Automatically constrained to caller customer UUID.
  - **Response (200 OK)**: Array of `BeneficiaryView`.

- **`POST /beneficiaries`**
  - **Description**: Creates a new beneficiary in `PENDING` status.
  - **Request Body (`CreateBeneficiary`)**:
    ```json
    {
      "customerId": "10000000-0000-4000-8000-000000000001",
      "name": "Jane Doe",
      "destinationAccountReference": "ACCT-99990001",
      "currency": "USD"
    }
    ```
  - **Authorization**: Verified via `verifyCustomerOwnership()`. Callers cannot register beneficiaries on behalf of other customers (`403 Forbidden`).
  - **Response (201 Created)**: Returns created beneficiary with `status: "PENDING"`.

- **`GET /beneficiaries/{id}`**
  - **Description**: Retrieves single beneficiary record.
  - **Authorization**: Requires ownership validation (`403 Forbidden` on mismatch).

- **`POST /beneficiaries/{id}/verify`**
  - **Description**: Simulates out-of-band verification (e.g. micro-deposit or SMS OTP) and promotes beneficiary status from `PENDING` to `VERIFIED`.
  - **Authorization**: Enforces customer ownership.
  - **Response (200 OK)**: Beneficiary with `status: "VERIFIED"`.

- **`GET /transactions`**
  - **Description**: Historical transaction ledger query. Automatically scoped to authenticated customer.
  - **Response (200 OK)**: Array of `TransactionView`.

- **`GET /transactions/{id}`**
  - **Description**: Retrieves transaction details by UUID. Enforces ownership (`403 Forbidden` if customer != transaction owner).

- **`POST /transfers`**
  - **Description**: Executes end-to-end fund transfer between accounts.
  - **Headers**: `Idempotency-Key` (optional, falls back to `request.reference`).
  - **Request Body (`TransferRequest`)**:
    ```json
    {
      "customerId": "10000000-0000-4000-8000-000000000001",
      "sourceAccountId": "20000000-0000-4000-8000-000000000001",
      "beneficiaryId": "30000000-0000-4000-8000-000000000001",
      "amount": 150.0000,
      "currency": "USD",
      "reference": "TX-SIM-001"
    }
    ```
  - **Multi-Service Workflow**:
    1. Validates customer ownership of request (`verifyCustomerOwnership`).
    2. Checks idempotency: if reference exists and matches request, returns existing transaction; if mismatched, returns `409 Conflict`.
    3. Retrieves beneficiary from DB: verifies customer ownership (`403 Forbidden` if mismatched) and verifies `status == "VERIFIED"` (`409 Conflict` if still `PENDING`).
    4. Calls Account Service (`GET /accounts/{sourceAccountId}`) via `AccountClient`: verifies customer ownership (`403 Forbidden` if mismatched), verifies account `status == "ACTIVE"`, verifies currency match, and verifies available balance.
    5. Saves transaction in `PENDING` state.
    6. Calls Account Service (`POST /accounts/{sourceAccountId}/debits`) to atomically deduct funds.
    7. Transitions transaction to `AUTHORIZED` then `COMPLETED` and returns `201 Created`.

---

### 2.3 Database Entities & Relationships

```
 ┌────────────────────────┐
 │ customer_data.customers│
 ├────────────────────────┤
 │ id (UUID, PK)          │◄──────────────────────┐
 │ customer_number (UQ)   │                       │
 │ first_name / last_name │                       │
 │ email (UQ)             │                       │
 │ country_code           │                       │
 │ status (ACTIVE/...)    │                       │
 │ created_date           │                       │
 └────────────────────────┘                       │
             ▲                                    │ (logical reference)
             │ (logical reference)                │
 ┌───────────┴────────────┐             ┌─────────┴─────────────────────┐
 │  account_data.accounts │             │ transaction_data.beneficiaries│
 ├────────────────────────┤             ├───────────────────────────────┤
 │ id (UUID, PK)          │◄──────┐     │ id (UUID, PK)                 │◄──────┐
 │ account_number (UQ)    │       │     │ customer_id (UUID)            │       │
 │ customer_id (UUID)     │       │     │ name                          │       │
 │ currency               │       │     │ destination_account_reference │       │
 │ balance                │       │     │ currency                      │       │
 │ status                 │       │     │ status (PENDING/VERIFIED)     │       │
 │ opened_at              │       │     │ created_at                    │       │
 └────────────────────────┘       │     └───────────────────────────────┘       │
             ▲                    │                    ▲                        │
             │                    │                    │                        │
             │ (FK)               │ (logical reference)│ (FK)                   │
 ┌───────────┴───────────────┐    │     ┌──────────────┴────────────────┐       │
 │account_data.account_debits│    └─────│  transaction_data.transactions│       │
 ├───────────────────────────┤          ├───────────────────────────────┤       │
 │ id (UUID, PK)             │          │ id (UUID, PK)                 │       │
 │ account_id (UUID, FK)     │          │ reference (UQ)                │       │
 │ reference (UQ)            │          │ customer_id (UUID)            │       │
 │ amount                    │          │ source_account_id (UUID)      │───────┘
 │ currency                  │          │ beneficiary_id (UUID, FK)     │───────┘
 │ debited_at                │          │ amount                        │
 └───────────────────────────┘          │ currency                      │
                                        │ status (COMPLETED/...)        │
                                        │ created_at / updated_at       │
                                        └───────────────────────────────┘
```

---

### 2.4 Existing Seed Data Audit

#### Customer Data (`customer_data.customers` via `V1__customer_schema.sql`):
1. `10000000-0000-4000-8000-000000000001` — `CUST-10001`, Alex Morgan, `alex.morgan@example.test`, US, `ACTIVE`
2. `10000000-0000-4000-8000-000000000002` — `CUST-10002`, Sam Taylor, `sam.taylor@example.test`, GB, `ACTIVE`
3. `10000000-0000-4000-8000-000000000003` — `CUST-10003`, Jordan Lee, `jordan.lee@example.test`, CA, `SUSPENDED`

#### Account Data (`account_data.accounts` via `V1__account_schema.sql`):
1. `20000000-0000-4000-8000-000000000001` — `ACCT-00010001`, Customer 1 (Alex Morgan), USD `$12,500.00`, `ACTIVE`
2. `20000000-0000-4000-8000-000000000002` — `ACCT-00010002`, Customer 1 (Alex Morgan), USD `$875.50`, `ACTIVE`
3. `20000000-0000-4000-8000-000000000003` — `ACCT-00020001`, Customer 2 (Sam Taylor), GBP `£5,300.25`, `ACTIVE`

#### Beneficiary & Transaction Data:
- **Zero initial records**. Beneficiaries and transactions must be dynamically created through the API during simulation setup.

---

## 3. Identity and Authentication Audit

### 3.1 Keycloak Realm & Client Architecture
- **Realm**: `aegis-dev` (imported from `keycloak/realm/aegis-dev-realm.json`).
- **Clients**:
  1. `aegis-local`: Public OIDC client, `standardFlowEnabled: true`, `directAccessGrantsEnabled: true` (supports Resource Owner Password Credentials Grant). Includes custom protocol mappers:
     - `customer-id-mapper`: Maps user attribute `customerId` to top-level JWT claim `customerId`.
     - `customer-number-mapper`: Maps user attribute `customerNumber` to top-level JWT claim `customerNumber`.
     - `audience-mapper`: Emits audience `aegis-api`.
  2. `aegis-frontend`: Public client configured with PKCE (S256) for Angular SOC Dashboard.
  3. `aegis-gateway`: Confidential service client (`serviceAccountsEnabled: true`).
- **Realm Roles**:
  - `CUSTOMER`: Standard banking customer role.
  - `SECURITY_ANALYST`: SOC analyst role (read-only posture, events, incidents, specs).
  - `SECURITY_ADMIN`: SOC admin role (status updates, spec management).

---

### 3.2 Provisioned Users in `aegis-dev-realm.json`

| Username | Realm Roles | `customerId` Claim | `customerNumber` Claim | Linked DB Record |
| :--- | :--- | :--- | :--- | :--- |
| `alex.morgan` | `CUSTOMER` | `10000000-0000-4000-8000-000000000001` | `CUST-10001` | **Yes**: Alex Morgan (`ACTIVE`) |
| `sam.taylor` | `CUSTOMER` | `10000000-0000-4000-8000-000000000002` | `CUST-10002` | **Yes**: Sam Taylor (`ACTIVE`) |
| `analyst` | `SECURITY_ANALYST` | *(none)* | *(none)* | N/A (SOC Operator) |
| `admin` | `SECURITY_ADMIN`, `SECURITY_ANALYST` | *(none)* | *(none)* | N/A (SOC Administrator) |

> [!IMPORTANT]
> **Jordan Lee Discrepancy**: Database customer `10000000-0000-4000-8000-000000000003` (Jordan Lee, `SUSPENDED`) does **not** have a corresponding user provisioned in `aegis-dev-realm.json`. Only two active customers currently exist in Keycloak.

---

### 3.3 Token Acquisition Flow
Synthetic traffic harnesses can acquire valid JWT access tokens directly using standard OAuth2 Direct Access Grants (`password` grant):

```http
POST /realms/aegis-dev/protocol/openid-connect/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded

client_id=aegis-local&grant_type=password&username=alex.morgan&password=[REDACTED]
```

**Resulting Token Claims Used by Aegis Gateway**:
- `sub`: Keycloak user UUID.
- `customerId`: UUID string (e.g. `10000000-0000-4000-8000-000000000001`).
- `customerNumber`: String identifier (e.g. `CUST-10001`).
- `realm_access.roles`: `["CUSTOMER", "default-roles-aegis-dev"]`.
- `aud`: `["aegis-api", "account"]`.

---

### 3.4 Gateway Perimeter Authentication & Internal Trust Propagation

1. **Perimeter Authorization (`SecurityConfig.java`)**:
   - `/actuator/**`: `permitAll()`
   - `/transfers/**`, `/api/v1/transfers/**`: Requires `ROLE_CUSTOMER`.
   - `/customers/**`, `/accounts/**`, `/beneficiaries/**`, `/transactions/**`: Requires `hasAnyRole('CUSTOMER', 'SECURITY_ANALYST', 'SECURITY_ADMIN')`.
   - `/api/v1/security/**`: Requires `hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')`.
   - Unauthenticated requests immediately receive `401 Unauthorized ProblemDetail`.
   - Lacking role receives `403 Forbidden ProblemDetail`.

2. **Internal Attestation Filter (`InternalTrustAttestationFilter.java`)**:
   When the Gateway routes a validated request to a downstream service, it computes an HMAC-SHA256 signature and injects five internal headers:
   - `X-Correlation-Id`: Client-supplied or Gateway-generated UUID.
   - `X-User-Id`: Extracted from JWT `sub`.
   - `X-Customer-Id`: Extracted from JWT claim `customerId`.
   - `X-Roles`: Extracted from `realm_access.roles`.
   - `X-Internal-Signature`: `HMAC_SHA256(correlationId|userId|customerId|roles|method|path|timestamp, internalSecret)`.

3. **Microservice Perimeter Enforcement (`InternalTrustFilter.java`)**:
   Every microservice validates `X-Internal-Signature` with a 60-second replay window.
   - Any external request attempting to reach `:8081`, `:8082`, or `:8083` directly without passing through the Gateway is rejected with:
     `403 Forbidden` (`"Gateway trust attestation missing or invalid"`).

---

## 4. Gateway Telemetry & Event Pipeline Audit

### 4.1 Telemetry Extraction Pipeline (`TelemetryFilter.java`)

The Gateway intercepts all requests/responses (excluding `/actuator/**`), records timestamps, extracts contextual metadata, and buffers request/response payloads:

```
 HTTP Request ──► [TelemetryFilter] ──► [SecurityFilterChain] ──► Downstream Service
                        │                                                │
                        ▼                                                ▼
               Payload & Path Inspection                          Response Status & Body
                        │                                                │
                        └───────────────┬────────────────────────────────┘
                                        ▼
                                 Construct ApiEvent
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 [Redis Stream]               [PostgreSQL Fallback]
             (aegis:stream:api-events)      (security_data.api_events)
                         │
                         ├─────────────────────────────┐
                         ▼                             ▼
              [TelemetryDrainWorker]      [DetectionStreamConsumer]
                         │                             │
                         ▼                             ▼
              Batch Write to Postgres        [ThreatDetectionEngine]
```

---

### 4.2 Telemetry Field Inventory (`ApiEvent.java`)

All events captured in `security_data.api_events` contain 20 discrete forensic attributes:

| Attribute | Data Type | Source / Derivation | Available for Scenario Analysis |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | Generated per request | Unique event identification |
| `correlationId` | `VARCHAR(64)` | Header `X-Correlation-Id` | End-to-end trace correlation |
| `timestamp` | `TIMESTAMPTZ` | Request execution time | Sliding-window timeline analysis |
| `sourceIp` | `VARCHAR(45)` | `X-Forwarded-For` or `remoteAddr` | Multi-source IP attack tracking |
| `httpMethod` | `VARCHAR(10)` | Request HTTP verb | Method tampering drift detection |
| `requestPath` | `VARCHAR(255)` | Raw URI | Exact resource path matching |
| `routeId` | `VARCHAR(255)` | `RouteNormalizer.normalize()` | Endpoint cataloging (`/customers/{id}`) |
| `statusCode` | `INTEGER` | HTTP response code (200, 401, 403, etc.) | Error distribution metrics |
| `latencyMs` | `BIGINT` | End-to-end execution duration | Performance & anomaly detection |
| `authSubject` | `VARCHAR(80)` | JWT `sub` claim or `"anonymous"` | Subject identity tracking |
| `authRoles` | `VARCHAR(255)` | Comma-delimited JWT roles | Role privilege analysis |
| `customerId` | `VARCHAR(40)` | JWT `customerId` claim | Cross-customer ownership verification |
| `userAgent` | `VARCHAR(255)` | Header `User-Agent` | Tooling identification (curl, python) |
| `payloadHash` | `VARCHAR(64)` | SHA-256 hex of request body | Payload change tracking |
| `anomalyFlags` | `VARCHAR(50)` | Regex/Status classifier | `INJECTION_INDICATOR`, `UNAUTHENTICATED_ACCESS`, `FORBIDDEN_ATTEMPT`, `VALIDATION_ERROR`, `SERVER_ERROR`, `NONE` |
| `resourceType` | `VARCHAR(40)` | Path pattern matcher | `CUSTOMER`, `CUSTOMER_PROFILE`, `ACCOUNT`, `ACCOUNT_BALANCE`, `ACCOUNT_LIST`, `TRANSFER`, `TRANSFER_EXECUTION`, `BENEFICIARY` |
| `resourceId` | `VARCHAR(80)` | Path / Query parameter extractor | Targeted entity identifier |
| `errorCode` | `VARCHAR(40)` | Status & body error parser | `INJECTION_DETECTED`, `BOLA_VIOLATION`, `INSUFFICIENT_ROLE`, `FORBIDDEN`, `UNAUTHENTICATED`, `VALIDATION_ERROR`, `NOT_FOUND`, `INTERNAL_ERROR` |
| `responseSizeBytes`| `BIGINT` | Response content byte length | Exfiltration volume tracking |
| `recordCount` | `INTEGER` | JSON array element counter | Bulk data scraping detection |

---

## 5. Security Controls & Scenario Feasibility Matrix

We audited the existing detection engine, sliding-window state store (`DetectionStateStore`), correlators, and posture assessment rules against nine distinct operational scenarios:

| # | Scenario | Required Endpoint | Synthetic Identity | Expected Response | Telemetry Signals | Target Detection Rule | Expected Incident / Posture Outcome | Feasibility Today |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **BOLA / Cross-Customer Probing** | `GET /api/v1/customers/{targetId}`<br>`GET /api/v1/accounts/{targetId}`<br>`GET /api/v1/accounts/{id}/balance` | Authenticated customer (e.g. Alex Morgan) targeting Sam Taylor's ID | `403 Forbidden` (`"Access to another customer's resources is forbidden"`) | `statusCode: 403`, `errorCode: "BOLA_VIOLATION"`, `customerId != resourceId` | **`RULE-BOLA-01`** | **Incident**: `THREAT_CATEGORY: BOLA`, Severity `HIGH`, Status `OPEN`.<br>**Posture**: `AUTHORIZATION: FINDING`, Overall `ATTENTION_REQUIRED`. | **100% Ready** ($\ge 3$ attempts on $\ge 2$ targets in 300s) |
| **2** | **Repeated Auth Failures / Credential Stuffing** | `GET /api/v1/accounts`<br>`GET /api/v1/customers/{id}` | Anonymous / Bad Bearer token / Expired token | `401 Unauthorized` (`ProblemDetail: "Full authentication is required"`) | `statusCode: 401`, `errorCode: "UNAUTHENTICATED"`, `anomalyFlags: "UNAUTHENTICATED_ACCESS"` | **`RULE-AUTH-01`** | **Incident**: `THREAT_CATEGORY: AUTH_FAILURE`, Target `IP: <srcIp>`, Severity `MEDIUM` (or `HIGH` if $\ge 10$ burst).<br>**Posture**: `AUTHENTICATION: FINDING`. | **100% Ready** ($\ge 5$ attempts in 120s) |
| **3** | **Authorization Failure / Role Escalation** | `GET /api/v1/security/posture`<br>`POST /api/v1/security/specs/import` | Customer role (`alex.morgan`) without analyst privileges | `403 Forbidden` (`ProblemDetail: "Access is denied"`) | `statusCode: 403`, `errorCode: "INSUFFICIENT_ROLE"`, `anomalyFlags: "FORBIDDEN_ATTEMPT"` | Gateway Security Filter Chain | **Incident**: Recorded in telemetry; triggers `RULE-PROBE-01` if combined with other 4xx.<br>**Posture**: Reflected in auth failure counts. | **100% Ready** |
| **4** | **API Probing & Directory Fuzzing** | `GET /api/v1/admin`<br>`GET /api/v1/internal/config`<br>`GET /api/v1/debug` | Any identity (anonymous or customer) | `404 Not Found` or `400 Bad Request` | `statusCode: 404`, `errorCode: "NOT_FOUND"`, distinct paths | **`RULE-PROBE-01`** | **Incident**: `THREAT_CATEGORY: PROBING`, Severity `HIGH`, Status `OPEN`.<br>**Posture**: `EXPOSURE: FINDING` on undocumented endpoints. | **100% Ready** ($\ge 4$ attempts across $\ge 3$ distinct paths in 180s) |
| **5** | **Rate Abuse & Flooding** | `GET /api/v1/accounts`<br>`GET /api/v1/transactions` | Authenticated customer or single source IP | `200 OK` (rapid bursts) | Rapid burst of events with identical customer/IP | **`RULE-RATE-01`** | **Incident**: `THREAT_CATEGORY: RATE_ABUSE`, Severity `MEDIUM` ($\ge 20$/60s) or `HIGH` ($\ge 40$/60s).<br>**Posture**: Evaluated under `BEHAVIORAL` dimension. | **100% Ready** ($\ge 20$ reqs in 60s) |
| **6** | **Injection Attempt (SQLi, Traversal, CMD)** | `GET /api/v1/accounts?customerId=1' OR '1'='1`<br>`GET /api/v1/customers/..%2f..%2fetc/passwd`<br>`GET /api/v1/beneficiaries?q=;id` | Any identity | Gateway logs telemetry with pattern flag | `anomalyFlags: "INJECTION_INDICATOR"`, `errorCode: "INJECTION_DETECTED"` | **`RULE-INJ-01`** | **Incident**: Immediate `THREAT_CATEGORY: INJECTION`, Severity `HIGH` (1 attempt) or `CRITICAL` ($\ge 2$ attempts in 180s). | **100% Ready** (Triggers on 1st attempt!) |
| **7** | **Excessive Data Access / Harvesting** | `GET /api/v1/beneficiaries`<br>`GET /api/v1/transactions` | Authenticated customer | `200 OK` with populated array response | `statusCode: 200`, `responseSizeBytes`, `recordCount >= 6` cumulative | **`RULE-DATA-01`** | **Incident**: `THREAT_CATEGORY: DATA_VOLUME`, Severity `MEDIUM`. | **Ready** (Requires pre-populated transactions/beneficiaries) |
| **8** | **Undocumented API Access & Shadow Drift** | `POST /api/v1/customers/10000000-0000-4000-8000-000000000001/archive`<br>`PUT /api/v1/accounts/20000000-0000-4000-8000-000000000001` | Customer or Analyst | Routes through Gateway to mock/service | Gateway records telemetry for uncataloged route | **Reconciliation & Posture Engine** | **Posture Outcome**: Categorized as `OBSERVED_UNDOCUMENTED` in reconciliation; `EXPOSURE: FINDING`; Overall Posture: `ATTENTION_REQUIRED`. | **100% Ready** |
| **9** | **Multi-Vector Attack Campaign** | Sequence: 1. Auth failure burst (`RULE-AUTH-01`)<br>2. Directory probe (`RULE-PROBE-01`)<br>3. Injection query (`RULE-INJ-01`) | Same Source IP (e.g. `198.51.100.42` via `X-Forwarded-For`) | Varied responses (`401`, `404`, `400`) | Multiple rule triggers correlating to single IP | **`MultiVectorCampaignCorrelator`** | **Incident**: Escalates existing incident to `THREAT_CATEGORY: MULTI_VECTOR_CAMPAIGN`, Severity `CRITICAL`, Status `INVESTIGATING`. | **100% Ready** ($\ge 2$ distinct attack vectors on same entity) |

---

## 6. Gaps, Missing Capabilities & Blockers

1. **No Dynamic Customer/Account Provisioning API**:
   - Customer Service and Account Service are completely read-only from the REST interface.
   - **Impact on Simulation**: We cannot register new customer accounts via REST API calls during simulation setup.
   - **Resolution**: The simulation environment must either rely on the existing pre-seeded customers (`Alex Morgan`, `Sam Taylor`), or seed synthetic accounts directly via SQL/migration, or use `POST /beneficiaries` and `POST /transfers` which *are* dynamically writable.

2. **Keycloak User Provisioning Bounded to 2 Active Customers**:
   - `aegis-dev-realm.json` contains only `alex.morgan` and `sam.taylor`.
   - `Jordan Lee` is in the database as `SUSPENDED`, but has no Keycloak user or password credentials.
   - **Impact on Simulation**: Multi-customer BOLA scenarios currently have exactly 2 valid customer tokens.
   - **Resolution**: Two active customers (`alex.morgan` as attacker, `sam.taylor` as victim) are sufficient to fully trigger `RULE-BOLA-01` (by probing Sam Taylor's customer record, accounts, and balance). Additional customers can be added to Keycloak realm or via the Keycloak Admin API if broader multi-tenant testing is required.

3. **OpenAPI Specifications Not Committed to Disk**:
   - Phase 6.2 implemented the specification import engine, but the official OpenAPI specs for Customer, Account, and Transaction services were tested in memory and not saved as static JSON/YAML files under version control.
   - **Impact on Simulation**: Without imported specifications, reconciliation categorizes *all* endpoints as `OBSERVED_UNDOCUMENTED` (shadow APIs).
   - **Resolution**: Phase 7.2 should include official OpenAPI 3.0 specification documents for Customer Service, Account Service, and Transaction Service under `simulation/specs/` and import them upon simulation initialization.

---

## 7. Recommended Simulation Architecture (`simulation/`)

We recommend implementing a dedicated `simulation/` module written in **Python 3.11+**, leveraging `httpx` (for high-concurrency async HTTP traffic generation), `pydantic` (for scenario configuration schemas), and `typer`/`rich` (for CLI execution and SOC evaluation reports).

### 7.1 Directory Layout Proposal
```
aegis/
├── simulation/
│   ├── pyproject.toml               # Poetry/pip dependencies (httpx, pydantic, typer, rich)
│   ├── README.md                    # Quickstart & CLI execution instructions
│   ├── config/
│   │   ├── simulation.env.example   # Base URLs, Gateway port, Keycloak client
│   │   └── default_scenarios.yaml  # Scenario definitions and sequence weights
│   ├── specs/
│   │   ├── customer-service.yaml    # OpenAPI 3.0 specification for Customer Service
│   │   ├── account-service.yaml     # OpenAPI 3.0 specification for Account Service
│   │   └── transaction-service.yaml # OpenAPI 3.0 specification for Transaction Service
│   ├── src/
│   │   ├── __init__.py
│   │   ├── cli.py                   # Typer CLI entrypoint (`run`, `verify`, `report`)
│   │   ├── auth.py                  # Token acquisition & session caching from Keycloak
│   │   ├── client.py                # Gateway HTTP client with correlation & IP injection
│   │   ├── models.py                # Scenario schemas, results, and evaluation DTOs
│   │   ├── scenarios/
│   │   │   ├── __init__.py
│   │   │   ├── base.py              # Abstract Scenario Runner
│   │   │   ├── legitimate_traffic.py# Normal customer transfers, balance checks, beneficiaries
│   │   │   ├── bola_attack.py       # Cross-customer resource enumeration (RULE-BOLA-01)
│   │   │   ├── credential_burst.py  # Repeated 401 auth failures (RULE-AUTH-01)
│   │   │   ├── api_fuzzing.py       # Probing unmapped paths and invalid schemas (RULE-PROBE-01)
│   │   │   ├── injection_attack.py  # SQLi, directory traversal, cmd injection (RULE-INJ-01)
│   │   │   ├── data_harvesting.py   # Bulk transaction/beneficiary scraping (RULE-DATA-01)
│   │   │   ├── rate_abuse.py        # High-frequency burst flooding (RULE-RATE-01)
│   │   │   └── multi_vector.py      # Blended multi-step attack campaign
│   │   └── verification.py          # Queries Gateway SOC API to assert incident creation
│   └── tests/
│       └── test_scenarios.py        # Pytest integration tests for simulation runner
```

---

### 7.2 Synthetic Traffic & Execution Strategy

1. **Phase 1: Environment Initialization & Spec Import**:
   - Verify health of all containers (`:8000`, `:8080`, `:8081`, `:8082`, `:8083`).
   - Acquire `analyst` or `admin` JWT from Keycloak.
   - Import OpenAPI specs (`customer-service.yaml`, `account-service.yaml`, `transaction-service.yaml`) via `POST /api/v1/security/specs/import`.
   - Baseline API Posture: endpoints become documented contracts.

2. **Phase 2: Legitimate Background Traffic Generation**:
   - Log in as `alex.morgan` and `sam.taylor`.
   - Alex checks profile, views accounts, checks balance, creates beneficiary ("Sam Taylor"), verifies beneficiary, and initiates a $150 transfer.
   - Generates clean 200 OK telemetry, populates `account_debits` and `transactions` tables.

3. **Phase 3: Controlled Adversarial Attack Injection**:
   - **BOLA Attack**: `alex.morgan` attempts to access Sam Taylor's customer profile (`GET /api/v1/customers/10000000-0000-4000-8000-000000000002`), Sam's account (`GET /api/v1/accounts/20000000-0000-4000-8000-000000000003`), and Sam's balance in rapid succession ($> 3$ attempts across 2 targets).
   - **Injection Attack**: Injects `' OR '1'='1` and `../etc/passwd` payloads from synthetic attacker IP (`198.51.100.42` via `X-Forwarded-For`).
   - **Credential Stuffing**: Sends 6 consecutive invalid bearer tokens to `/api/v1/accounts`.
   - **Probing**: Probes `/api/v1/admin`, `/api/v1/debug`, `/api/v1/v2/keys`.

4. **Phase 4: Automated Verification & Evaluation Report**:
   - Query `GET /api/v1/security/incidents` to assert that:
     - Incident with `RULE-BOLA-01` was created with `status: OPEN`.
     - Incident with `RULE-INJ-01` was created with severity `CRITICAL`.
     - Incident with `RULE-AUTH-01` was created.
   - Query `GET /api/v1/security/posture` to assert that:
     - Target endpoints transition from `ADEQUATE` to `ATTENTION_REQUIRED`.
     - `AUTHORIZATION` and `AUTHENTICATION` dimensions show `FINDING`.
     - Invariant `confirmedVulnerability: false` is preserved across all endpoints.

---

## 8. Recommended Implementation Sequence for Phase 7.2

1. **Step 1: Create OpenAPI Specifications**:
   Author valid, complete OpenAPI 3.0 specifications for Customer, Account, and Transaction services under `simulation/specs/`.
2. **Step 2: Scaffold Python Simulation Framework**:
   Create `simulation/` directory with `pyproject.toml`, Keycloak auth manager, and Gateway client supporting custom `X-Forwarded-For` and `X-Correlation-Id` headers.
3. **Step 3: Implement Legitimate FinTech Workflows**:
   Implement automated banking journeys (registration of beneficiaries, verification, fund transfers, balance reconciliation).
4. **Step 4: Implement Adversarial Attack Scenarios**:
   Implement targeted modules for BOLA, Injection, Auth Failure Bursts, Directory Probing, Rate Abuse, and Multi-Vector Campaigns.
5. **Step 5: Implement Post-Simulation SOC Verification**:
   Build automated assertions against Aegis Gateway REST APIs (`/api/v1/security/events`, `/api/v1/security/incidents`, `/api/v1/security/posture`) to verify detection accuracy and evidence recording.
6. **Step 6: CLI & Automation Harness**:
   Provide a unified CLI command (e.g. `python -m simulation.cli run --scenario all --verify`) with rich terminal reporting.

---

## 9. Implementation Progress & Milestone Tracking

- **Phase 7.2.1 (Completed — 2026-11-02):** Established authoritative FinTech API Contract Baseline in `simulation/specs/customer-service.yaml`, `simulation/specs/account-service.yaml`, and `simulation/specs/transaction-service.yaml` (12 declared operations). Verified 100% pass via `FintechSpecificationBaselineTest` in gateway. Complete documentation in `docs/phase-7-2-1-api-contract-baseline.md`.
- **Phase 7.2.2 (Pending):** Multi-Customer Synthetic Identity & Keycloak User Provisioning.
- **Phase 7.2.3 (Pending):** Realistic Traffic & Adversarial Simulation Engine.


