# Aegis Phase 7.2.1 — FinTech API Contract Baseline Specification

**Document Version:** 1.0.0  
**Status:** Completed & Verified  
**Date:** 2026-11-02  
**Target Services:** Customer Service, Account Service, Transaction Service  
**Gateway Routes:** `/api/v1/customers/**`, `/api/v1/accounts/**`, `/api/v1/beneficiaries/**`, `/api/v1/transactions/**`, `/api/v1/transfers`

---

## 1. Executive Summary & Objective

In Phase 7.2.1, Aegis establishes an authoritative, version-controlled OpenAPI 3.0.3 contract baseline for the existing FinTech microservices (`customer-service`, `account-service`, and `transaction-service`).

These contract specifications reflect the actual, authoritative implementations of the microservices and their exposed Spring Cloud Gateway routes. They serve as the foundational documented ground truth for:
1. **API Discovery Reconciliation (Phase 6.3):** Matching observed passive wire telemetry against declared operations.
2. **Discrepancy Prioritization (Phase 6.4):** Scoring and triaging undocumented endpoints, method mismatches, and unobserved routes.
3. **API Security Posture Assessment (Phase 7.1):** Evaluating authentication coverage, parameter validation, role requirements, and sensitive data exposure.
4. **Synthetic FinTech Traffic Simulation (Phase 7.2):** Validating realistic legitimate and adversarial workflows against known API contracts.

---

## 2. Specification Files & Boundary Architecture

All three OpenAPI specifications are stored under `simulation/specs/` and conform to OpenAPI 3.0.3:

| Specification File | Service Boundary | Title | Declared Operations | Accessible Gateway Routes |
| :--- | :--- | :--- | :---: | :--- |
| `simulation/specs/customer-service.yaml` | `customer-service` | `Customer Service API` (v1.0.0) | 2 | `/api/v1/customers/{customerId}`, `/api/v1/customers/{customerId}/profile` |
| `simulation/specs/account-service.yaml` | `account-service` | `Account Service API` (v1.0.0) | 3 | `/api/v1/accounts`, `/api/v1/accounts/{accountId}`, `/api/v1/accounts/{accountId}/balance` |
| `simulation/specs/transaction-service.yaml` | `transaction-service` | `Transaction Service API` (v1.0.0) | 7 | `/api/v1/beneficiaries`, `/api/v1/beneficiaries/{beneficiaryId}`, `/api/v1/beneficiaries/{beneficiaryId}/verify`, `/api/v1/transactions`, `/api/v1/transactions/{transactionId}`, `/api/v1/transfers` |
| **Total Baseline** | **3 Microservices** | — | **12** | **11 Unique Paths (12 Operations)** |

### 2.1 Route Normalization & Service Boundary Alignment

To ensure seamless reconciliation with passive gateway telemetry, all operations are declared using the externally accessible `/api/v1` gateway path prefix:
- `RouteNormalizer.normalize(path)` preserves `/api/v1/...` prefixes, parameterizing UUID segments into `{customerId}`, `{accountId}`, `{beneficiaryId}`, and `{transactionId}`.
- `RouteNormalizer.resolveService(route)` deterministically maps routes to `customer-service`, `account-service`, and `transaction-service`.
- When raw gateway events arrive, their normalized route and HTTP method match the declared operations with 100% precision (`MATCHED` status).

### 2.2 Public Gateway Routes vs. Internal Microservice Endpoints

A critical requirement of Phase 7.2.1 is strictly documenting only externally exposed APIs while excluding internal service-to-service routes:
- **Internal Debit Route:** `POST /accounts/{id}/debits` in `account-service` is an internal endpoint invoked exclusively by `transaction-service` via Feign/HTTP `AccountClient`. The Aegis Gateway explicitly restricts account routes to `HttpMethod.GET` (`/api/v1/accounts/**`). Consequently, `POST /accounts/{id}/debits` is not exposed publicly and is intentionally excluded from the public OpenAPI specification.

---

## 3. Microservice Contract Details

### 3.1 Customer Service (`customer-service.yaml`)

- **Security Scheme:** `bearerAuth` (JWT Bearer Token via Keycloak OIDC).
- **Required Roles:** `ROLE_CUSTOMER` (enforcing self-ownership) or `ROLE_SECURITY_ANALYST` / `ROLE_SECURITY_ADMIN` (privileged read).
- **Operations:**
  1. `GET /api/v1/customers/{customerId}` (`operationId: getCustomer`):
     - Path Parameter: `customerId` (UUID, required).
     - Response 200: `CustomerView` (`id`, `customerNumber`, `firstName`, `lastName`, `status`, `createdDate`).
     - Error Responses: 401 Unauthorized, 403 Forbidden (BOLA cross-customer violation), 404 Not Found.
  2. `GET /api/v1/customers/{customerId}/profile` (`operationId: getCustomerProfile`):
     - Path Parameter: `customerId` (UUID, required).
     - Response 200: `CustomerProfile` (`id`, `customerNumber`, `firstName`, `lastName`, `email`, `countryCode`, `status`).
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found.

### 3.2 Account Service (`account-service.yaml`)

- **Security Scheme:** `bearerAuth` (JWT Bearer Token).
- **Required Roles:** `ROLE_CUSTOMER`, `ROLE_SECURITY_ANALYST`, `ROLE_SECURITY_ADMIN`.
- **Operations:**
  1. `GET /api/v1/accounts` (`operationId: listAccounts`):
     - Query Parameter: `customerId` (UUID, optional filter for privileged analysts; non-privileged callers restricted to own customer ID).
     - Response 200: Array of `AccountView` (`id`, `accountNumber`, `customerId`, `currency`, `balance`, `status`, `openedAt`, `customer`).
     - Error Responses: 401 Unauthorized, 403 Forbidden.
  2. `GET /api/v1/accounts/{accountId}` (`operationId: getAccount`):
     - Path Parameter: `accountId` (UUID, required).
     - Response 200: `AccountView` with embedded `CustomerSummary`.
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found, 502 Bad Gateway (if downstream customer service is unavailable).
  3. `GET /api/v1/accounts/{accountId}/balance` (`operationId: getAccountBalance`):
     - Path Parameter: `accountId` (UUID, required).
     - Response 200: `Balance` (`accountId`, `currency`, `availableBalance`, `status`).
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found.

### 3.3 Transaction Service (`transaction-service.yaml`)

- **Security Scheme:** `bearerAuth` (JWT Bearer Token).
- **Required Roles:** `ROLE_CUSTOMER`, `ROLE_SECURITY_ANALYST`, `ROLE_SECURITY_ADMIN`.
- **Operations:**
  1. `GET /api/v1/beneficiaries` (`operationId: listBeneficiaries`):
     - Query Parameter: `customerId` (UUID, optional).
     - Response 200: Array of `BeneficiaryView`.
     - Error Responses: 401 Unauthorized, 403 Forbidden.
  2. `POST /api/v1/beneficiaries` (`operationId: createBeneficiary`):
     - Request Body: `CreateBeneficiary` (`customerId`, `name`, `destinationAccountReference`, `currency`).
     - Response 201: Created `BeneficiaryView` (default status `PENDING`).
     - Error Responses: 400 Bad Request, 401 Unauthorized, 403 Forbidden.
  3. `GET /api/v1/beneficiaries/{beneficiaryId}` (`operationId: getBeneficiary`):
     - Path Parameter: `beneficiaryId` (UUID, required).
     - Response 200: `BeneficiaryView`.
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found.
  4. `POST /api/v1/beneficiaries/{beneficiaryId}/verify` (`operationId: verifyBeneficiary`):
     - Path Parameter: `beneficiaryId` (UUID, required).
     - Response 200: Updated `BeneficiaryView` (`status: VERIFIED`).
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict (already verified).
  5. `GET /api/v1/transactions` (`operationId: listTransactions`):
     - Query Parameter: `customerId` (UUID, optional).
     - Response 200: Array of `TransactionView`.
     - Error Responses: 401 Unauthorized, 403 Forbidden.
  6. `GET /api/v1/transactions/{transactionId}` (`operationId: getTransaction`):
     - Path Parameter: `transactionId` (UUID, required).
     - Response 200: `TransactionView`.
     - Error Responses: 401 Unauthorized, 403 Forbidden, 404 Not Found.
  7. `POST /api/v1/transfers` (`operationId: executeTransfer`):
     - Request Header: `Idempotency-Key` (string, max 128, optional).
     - Request Body: `TransferRequest` (`customerId`, `sourceAccountId`, `beneficiaryId`, `amount`, `currency`, `reference`).
     - Response 201: Completed `TransactionView`.
     - Error Responses: 400 Bad Request, 401 Unauthorized, 403 Forbidden, 409 Conflict (insufficient funds / unverified beneficiary / duplicate idempotency), 502 Bad Gateway.

---

## 4. Automated Verification & Baseline Reconciliation Testing

A dedicated automated test suite (`FintechSpecificationBaselineTest.java`) validates the contract baseline:

1. **Parser & Structural Validation:**
   - Evaluates all YAML specifications against `OpenApiParser.parseAndValidate()`.
   - Confirms zero syntax, recursion, or safety violations.
   - Verifies declared operation counts: Customer (2), Account (3), Transaction (7).
   - Validates that normalized routes match `RouteNormalizer` patterns and map to correct service boundaries.
2. **Database Import & Persistence:**
   - Imports all three specifications via `ApiSpecificationService.importSpecification()`.
   - Asserts insertion of 3 rows in `security_data.api_specifications` and 12 rows in `security_data.api_spec_operations`.
3. **Baseline Reconciliation:**
   - Executes `ApiReconciliationService.reconcile()` across the newly imported baseline.
   - Confirms that in the absence of traffic, all 12 declared operations are properly classified as `DOCUMENTED_UNOBSERVED`.
   - Confirms 0 `OBSERVED_UNDOCUMENTED`, 0 `MATCHED`, and 0 `METHOD_MISMATCH`.

### Test Execution Results
```
[INFO] Running com.aegis.gateway.specs.FintechSpecificationBaselineTest
[INFO] Tests run: 4, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 12.41 s
[INFO] BUILD SUCCESS
```

---

## 5. Next Steps

With the API contract baseline established and verified, subsequent steps of Phase 7.2 will proceed:
- **Phase 7.2.2:** Multi-Customer Synthetic Identity & Seed Data Provisioning (Keycloak users, realistic accounts, balances, and beneficiaries).
- **Phase 7.2.3:** Realistic HTTP Traffic & Attack Simulation Engine (autonomous Python simulation generating legitimate customer flows and targeted security scenario attacks through the Aegis Gateway).
