# Aegis Phase 7.1 — API Security Posture Assessment Engine

## 1. Executive Summary

Aegis Phase 7.1 introduces the **API Security Posture Assessment Engine**, delivering a unified, deterministic, evidence-driven evaluation of discovered API endpoints across six independent security dimensions.

Building upon the completed Phase 6.1–6.5 foundation:
- **Phase 6.1**: Telemetry-based runtime discovery (`security_data.api_events`)
- **Phase 6.2**: Secure OpenAPI 3.0/3.1 specification import (`security_data.api_specifications`)
- **Phase 6.3**: Runtime vs. declared contract reconciliation (`ApiReconciliationService`)
- **Phase 6.4**: Discrepancy prioritization & forensic investigation (`ApiDiscrepancyPrioritizer`)
- **Phase 6.5**: Endpoint intelligence, time-bucketed observation history, and specification evolution

Phase 7.1 answers essential security questions for analysts:
1. What security properties are verified by concrete evidence?
2. Which security concerns or anomalies have been detected?
3. Which dimensions cannot currently be verified (`UNKNOWN`) due to observation boundaries?
4. Why was an endpoint assigned a particular categorical posture?
5. What actionable investigation steps should the analyst pursue next?

---

## 2. Six Posture Assessment Dimensions

Every discovered endpoint is evaluated across six orthogonal, evidence-aware dimensions. Each dimension produces a status (`VERIFIED`, `FINDING`, `UNKNOWN`), a summary, supporting evidence items with source provenance, observability boundary limitations, and recommended actions:

| Dimension | Scope & Evidence Evaluated | Status Transitions | Observability Limitations |
| :--- | :--- | :--- | :--- |
| **`EXPOSURE`** | Evaluates whether the endpoint is cataloged, declared in an OpenAPI spec, and actively observed in telemetry. | `VERIFIED`: Matched to specification and active on wire.<br>`FINDING`: `OBSERVED_UNDOCUMENTED` (shadow API) or `METHOD_MISMATCH`.<br>`UNKNOWN`: Zero traffic observed in observation window. | Observability bounded by selected telemetry window (1–720h). |
| **`AUTHENTICATION`** | Evaluates perimeter protection rules, Spring Security filter chains, OpenAPI security declarations, and 401 telemetry. | `VERIFIED`: Route mapped to Gateway auth perimeter or explicitly public (`/actuator/**`).<br>`FINDING`: Elevated 401 failure rate (>10% with >=5 failures).<br>`UNKNOWN`: Unmapped perimeter route with unverified token flow. | 401 is not proof every request is authenticated; perimeter auth does not verify microservice session invalidation timing. |
| **`AUTHORIZATION`** | Evaluates object-level authorization signals, elevated 403 telemetry, and correlated BOLA incident findings (`RULE-BOLA-01`). | `VERIFIED`: Microservice-level authorization policy verified.<br>`FINDING`: Correlated BOLA incident or elevated 403 failure rate (>10% with >=5 failures).<br>`UNKNOWN`: Successful 200 responses without application-layer data ownership proof. | 200 is not proof of unauthorized access; 403 is not proof authorization is correct. Gateway cannot inspect microservice DB data ownership on 200s. |
| **`DATA_SENSITIVITY`** | Evaluates explicit data sensitivity classifications and declared PII annotations in OpenAPI metadata. | `VERIFIED`: Explicitly configured data classification.<br>`FINDING`: Unprotected transmission of confirmed classified data.<br>`UNKNOWN`: Strictly assigned when explicit classification metadata is absent. | **Strict Invariant**: Automatic keyword matching (e.g. `customer`, `account`, `ssn`) is prohibited to prevent false assumptions. |
| **`BEHAVIORAL`** | Evaluates operational request volume, HTTP status distribution, anomaly scores, and correlated security incidents. | `VERIFIED`: Normal status distribution (>=5 requests, 0 incidents).<br>`FINDING`: Correlated security incidents or anomaly flags.<br>`UNKNOWN`: Sparse traffic (<5 requests). | High request volume alone is never classified as malicious; telemetry reflects aggregate window metrics only. |
| **`SPECIFICATION`** | Evaluates OpenAPI contract matching, active revision number, drift category, and discrepancy priority score. | `VERIFIED`: Matched to active revision with LOW discrepancy priority.<br>`FINDING`: Undocumented operation, method mismatch, or elevated priority.<br>`UNKNOWN`: Unobserved contract operation. | Reconciliation verifies method and path pattern congruence; payload schema drift requires explicit schema diffing. |

---

## 3. Mathematical Posture Model & Invariants

### 3.1 Categorical Overall Posture
The overall posture is deterministically derived from dimensional states:
- **`ATTENTION_REQUIRED`**: When at least one dimension evaluates to `FINDING`.
- **`INSUFFICIENT_EVIDENCE`**: When no dimensions have `FINDING`, but 3 or more dimensions evaluate to `UNKNOWN`.
- **`ADEQUATE`**: When no dimensions have `FINDING` and fewer than 3 dimensions are `UNKNOWN` (at least 4 dimensions verified).

### 3.2 Evidence Coverage Metric
Evidence coverage represents the percentage of verified knowledge across all six dimensions:
$$\text{evidenceCoveragePercentage} = \frac{6 - \text{unknownCount}}{6.0} \times 100.0$$

### 3.3 Strict Architectural Invariants
1. **`confirmedVulnerability: false`**: Guaranteed on 100% of responses. Discrepancies and posture gaps represent unverified contracts or elevated telemetry signals, NOT confirmed exploitable vulnerabilities.
2. **Strict Prohibition on Keyword-Based PII Inference**: `DATA_SENSITIVITY` must evaluate to `UNKNOWN` unless backed by explicit configuration. Inferring PII from route terms (such as `/customers/{id}` or `/accounts`) is strictly forbidden.
3. **Absence of Evidence is Never Evidence of Absence**: Missing telemetry is categorized as `UNKNOWN`, never converted into speculative positive or negative security conclusions.
4. **Advisory Assessment Scope**: Purely advisory. The engine does not block traffic, modify gateway routes, revoke tokens, or claim vulnerabilities without sufficient evidence.

---

## 4. REST API Route Contracts

All endpoints enforce Spring Security role-based access control requiring `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`.

### 4.1 Paginated Posture Assessment
- **Route**: `GET /api/v1/security/posture`
- **Parameters**:
  - `page` (default: 0, min: 0)
  - `size` (default: 20, max: 100)
  - `service` (optional service boundary filter)
  - `posture` (optional `ADEQUATE`, `ATTENTION_REQUIRED`, `INSUFFICIENT_EVIDENCE`)
  - `dimension` (optional dimension filter)
  - `dimensionStatus` (optional `VERIFIED`, `FINDING`, `UNKNOWN`)
  - `search` (optional substring match on route or method)
  - `windowHours` (default: 24, bounds: 1–720)
- **Response**: `PosturePageResponse` containing paginated `EndpointPostureResponse` items and `PostureSummaryResponse`.

### 4.2 Endpoint Posture Dossier
- **Route**: `GET /api/v1/security/posture/{id}`
- **Parameters**: `id` (16-char deterministic hex identifier), `windowHours` (optional, 1–720)
- **Response**: Full `EndpointPostureResponse` with all 6 dimensions, evidence items, limitations, and recommended steps.
- **Errors**: RFC 7807 `ProblemDetail` with 404 for unknown endpoint ID.

### 4.3 Posture Summary Metrics
- **Route**: `GET /api/v1/security/posture/summary`
- **Parameters**: `service` (optional), `windowHours` (optional, 1–720)
- **Response**: `PostureSummaryResponse` with evaluated endpoint counts, categorical posture distribution, dimension verification counts, and service distribution.

---

## 5. Angular SOC UI Implementation

A dedicated, production-grade interface was implemented in `frontend/src/app/features/api-posture/`:
- **Wallarm SOC Theme & Strict Inter 400 Typography**: All headers, body labels, table items, and cards strictly adhere to standard 400 weight typography with high-contrast dark theme styling (`#0d1117`, `#161b22`, `#30363d`).
- **5 KPI Summary Cards**: Total Assessed, Adequate Posture (green), Attention Required (amber), Insufficient Evidence (slate), and Average Evidence Coverage % (cyan).
- **Filter Toolbar**: Instant search by route template, service boundary dropdown, posture category dropdown, observation window selector (24h, 72h, 168h, 720h), and refresh action.
- **Interactive Posture Table**: Method badges, route & service display, overall posture pill, evidence coverage progress bar, 6 dimension mini-pills (`EXP`, `AUTH`, `AUTHZ`, `SENS`, `BEH`, `SPEC`), findings count badge, total observed traffic, and "Inspect" button.
- **Slide-out Forensic Posture Drawer**:
  - Endpoint identity and rule version tag (`v1.0.0`).
  - Safety Attestation banner: `CONFIRMED VULNERABILITY: NO — ADVISORY ASSESSMENT ONLY`.
  - Overall explanation banner with coverage percentage.
  - Deep-link action bar: View Telemetry (`/events`), API Inventory (`/api-inventory`), Reconciliation (`/api-reconciliation`), Related Incidents (`/incidents`).
  - Dimension cards with status badges, summaries, supporting evidence lists with provenance tags, observability boundary limitations, and recommended actions.
  - Prioritized next investigation steps.

---

## 6. Automated Verification & Test Results

### 6.1 Backend Test Results
- `ApiPostureAssessmentEngineTest`: **9 tests run, 0 failures, 0 errors**
  - Verified pure unit evaluation across all 6 dimensions.
  - Verified strict `DATA_SENSITIVITY` invariant (routes with `/customers/{id}` evaluate to `UNKNOWN`).
  - Verified `confirmedVulnerability: false` invariant.
  - Verified deterministic output across consecutive assessments.
- `SecurityPostureControllerTest`: **9 tests run, 0 failures, 0 errors**
  - Unauthenticated request returns 401 Unauthorized ProblemDetail.
  - Role `CUSTOMER` returns 403 Forbidden ProblemDetail.
  - Analyst retrieves paginated posture assessments and summary metrics.
  - Individual endpoint retrieval by deterministic ID.
  - Parameter validation for `windowHours` (1–720), `posture`, and `dimension`.
  - Unknown endpoint ID returns 404 ProblemDetail.
- **Full Gateway Regression Suite**: **50 tests run, 0 failures, 0 errors** (Intelligence, Evolution, Discovery, Specifications, Posture).

### 6.2 Frontend Test Results
- **Karma / Jasmine Suite**: **134 tests run, 0 failures, 0 errors**
  - `ApiPostureComponent`: 6 comprehensive unit tests covering initialization, KPI card rendering, search filtering, posture filtering, slide-out drawer inspection, invariant attestation, and error handling.
  - `SecurityApiService`: unit tests for `getPosturePage`, `getEndpointPosture`, `getPostureSummary`.
  - `SidebarComponent`: verified 17 navigation links including `Security Posture`.
- **Production Build**: `ng build` succeeded with **0 warnings, 0 errors** (initial bundle: 374.23 kB, transfer: 103.08 kB).
