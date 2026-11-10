# Aegis Phase 7.2.4.1 — Sensitive Data Classification Engine Implementation Report

## Executive Summary

Phase 7.2.4.1 establishes the foundational, deterministic, explainable data sensitivity classification engine across the Aegis FinTech microservice estate and integrates it directly into the ShieldOps SOC dashboard.

Prior to this phase, data sensitivity detection was either non-authoritative or relied on speculative heuristics. In Phase 7.2.4.1, a strict four-tier sensitivity taxonomy (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`) was designed and implemented at the field path level, covering all core FinTech endpoints (Customer, Account, Balance, Transaction, Beneficiary, Transfer, External Gateway, and Platform Observability).

## 1. Classification Architecture & Taxonomy

### 1.1 Data Sensitivity Taxonomy
1. **RESTRICTED**:
   - Authentication secrets, passwords, Bearer tokens, refresh tokens, signing keys, and private client credentials.
   - **Protection Invariant**: In telemetry and analytics, values are unconditionally replaced with `[REDACTED_RESTRICTED]`.
2. **CONFIDENTIAL**:
   - Customer personal identifying information (PII), email addresses, phone numbers, addresses, account identifiers, ledger balances, transaction amounts, debit receipts, and beneficiary references.
   - **Protection Invariant**: In telemetry and reporting, values are structurally masked (e.g. `a***@example.test`, `****0001`, `***.**`).
3. **INTERNAL**:
   - Internal operational information: service names, health checks, correlation IDs, timestamps, pagination parameters, telemetry flags, and metrics.
4. **PUBLIC**:
   - Open discovery metadata, unauthenticated OpenAPI specifications, public realm endpoints, and login form metadata.

### 1.2 Deterministic Field-Level Metadata Record
Every classified field carries an immutable schema record:
- `serviceBoundary`: Microservice owning the endpoint (`customer-service`, `account-service`, `transaction-service`, `gateway`, `external`).
- `httpMethod`: HTTP method (`GET`, `POST`, `PUT`, `DELETE`).
- `routeTemplate`: Normalized route template (e.g. `/api/v1/customers/{id}`).
- `fieldPath`: DTO property path, supporting dot notation and array wildcards (e.g. `items[*].amount`, `password`, `availableBalance`).
- `dataClassification`: Sensitivity level (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
- `classificationRationale`: Explainable compliance and security justification.
- `approvedAccessRoles`: RBAC roles authorized to access the field.
- `resourceOwnershipRequirements`: Subject-level ownership constraint (`NONE`, `OWNER_CUSTOMER`, `INTERNAL_SERVICE`, `ANALYST_ROLE`).
- `schemaSource`: Origin schema definition (`OPENAPI_DECLARED`, `OBSERVED_TELEMETRY`, `FRAMEWORK_CORE`).
- `confidence`: Confidence rating (`CONFIRMED`, `PROVISIONAL`, `UNKNOWN`).
- `policyVersion`: Deterministic policy version string (`v1.0.0-deterministic`).
- `manualReviewRequired`: Boolean flag triggering human analyst triage.

## 2. Implemented Backend Components

The classification engine is implemented in package `com.aegis.gateway.classification`:
- `DataSensitivityLevel.java`: Enum with strict comparison ranking (`RESTRICTED` > `CONFIDENTIAL` > `INTERNAL` > `PUBLIC`).
- `ResourceOwnershipRequirement.java`: Data ownership requirements enum.
- `ClassificationConfidence.java`: Confidence enum (`CONFIRMED`, `PROVISIONAL`, `UNKNOWN`).
- `FieldClassification.java`: Field-level metadata record.
- `EndpointDataClassification.java`: Endpoint consolidated dossier record.
- `ServiceClassificationSummary.java`: Service-level coverage breakdown record.
- `SensitiveDataInventorySummary.java`: Top-level platform coverage and counts summary record.
- `SensitiveDataInventoryPageResponse.java`: Paginated inventory response wrapper.
- `SensitiveDataClassificationEngine.java`: Authoritative deterministic classification engine covering:
  - Over 25 endpoints across Customer, Account, Transaction, External Gateway/Keycloak, Actuator, and SOC routes.
  - Conflict resolution: When overlapping rules match a field path, `DataSensitivityLevel.highest(a, b)` strictly prioritizes the higher sensitivity level.
  - Wildcard path matching (`*` and `**`) and exact field path matching.
  - Unknown field handling: unclassified fields default to `CONFIDENTIAL` with `UNKNOWN` confidence and `manualReviewRequired = true`.
  - Privacy-preserving value redaction and structural masking.
  - Coverage and distribution metric calculations.
- `SensitiveDataClassificationController.java`: REST controller under `/api/v1/security/classification`:
  - `GET /inventory`: Paginated and filterable endpoint inventory.
  - `GET /summary`: High-level platform coverage and service-wise breakdown.
  - `GET /endpoints/{id}`: Full field classification dossier for a single endpoint.
  - RBAC protection: Requires `SECURITY_ANALYST` or `SECURITY_ADMIN`.

## 3. Implemented Frontend Components (ShieldOps SOC Dashboard)

- **Models**: Added full TypeScript contracts in `frontend/src/app/core/models/security.models.ts`.
- **API Client**: Added `getSensitiveDataInventory`, `getSensitiveDataSummary`, and `getEndpointClassificationDetails` to `SecurityApiService`.
- **Feature Component**: Created `SensitiveDataComponent` in `frontend/src/app/features/sensitive-data/sensitive-data.component.ts`:
  - KPI summary cards (Monitored Endpoints, Discovered Fields, Classified Fields, Unclassified Fields, Overall Coverage %, Manual Review Required).
  - Sensitivity taxonomy cards (`RESTRICTED`, `CONFIDENTIAL`, `INTERNAL`, `PUBLIC`) with interactive filter toggles.
  - Service-wise coverage breakdown table with coverage progress bars.
  - Composite search and filter toolbar (route template, field path, service, sensitivity, manual review).
  - Expandable endpoint dossiers with field-level inspection table, approved roles, and privacy redaction invariants.
- **Routing & Navigation**:
  - Registered route `/sensitive-data` with `authGuard` in `app.routes.ts`.
  - Added "Sensitive Data Inventory" nav item in `nav-registry.ts` under `API SECURITY`.
- **Build Verification**: Production build succeeded with zero errors (`chunk-K33ECIKY.js | sensitive-data-component | 38.29 kB`).

## 4. Verification & Automated Test Results

1. **Gateway Backend Tests**:
   - `SensitiveDataClassificationEngineTest.java` (9 unit tests): Passed.
   - `SensitiveDataClassificationControllerTest.java` (5 integration tests): Passed.
   - Total backend tests: **329/329 passing** (258 gateway tests).
2. **Frontend Test Suite**:
   - `sensitive-data.component.spec.ts` (6 unit tests created).
   - `security-api.service.spec.ts` (3 new tests added for classification endpoints).
   - Production bundle compiled in 15.25s (`npm --prefix frontend run build` exited with code 0).

## 5. Milestone Status

- **Status**: `CLASSIFICATION_IMPLEMENTED`
- **Next Steps**: Phase 7.2.4.2 — Telemetry-Driven Data Leakage Detection & BOLA Correlation.
