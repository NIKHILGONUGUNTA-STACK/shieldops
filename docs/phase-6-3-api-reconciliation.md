# Aegis Phase 6.3 — Documented vs. Observed API Reconciliation Architecture & Implementation

## 1. Executive Summary

Aegis Phase 6.3 delivers a real-time, deterministic API reconciliation engine and SOC dashboard that bridges observed runtime telemetry (Phase 6.1) against declared OpenAPI specifications (Phase 6.2).

Without requiring synthetic test generation, active intrusive probing, or opaque machine learning models, the reconciliation engine performs canonical identity alignment between gateway wire events (`security_data.api_events`) and declared OpenAPI operations (`security_data.api_spec_operations`). The resulting inventory illuminates verified contract coverage, uncataloged shadow APIs, unexercised dead code, and HTTP verb drift.

Crucially, the SOC interface adheres to defensive security semantics: discrepancy findings provide actionable visibility and provenance explanations without assuming that an unobserved or undocumented endpoint constitutes an immediate vulnerability.

---

## 2. Architectural Blueprint

```
                      +------------------------------------------+
                      |         OpenAPI Specifications           |
                      |   security_data.api_spec_operations      |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |         Gateway Wire Telemetry           |
                      |       security_data.api_events           |
                      |    (Filtered by window: 1h - 720h)       |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |        ApiReconciliationRepository       |
                      |   - Dynamic windowed telemetry aggregate |
                      |   - Service & specification scope filter |
                      |   - Single-pass relational extraction    |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |         ApiReconciliationService         |
                      |   - Route normalizer synchronization     |
                      |   - Strict category precedence engine    |
                      |   - Disjoint partitioning (sum = total)  |
                      |   - Coverage percentage calculation      |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |    SecurityReconciliationController      |
                      |   - GET /api/v1/security/reconciliation  |
                      |   - GET /.../reconciliation/summary      |
                      |   - @PreAuthorize: ANALYST / ADMIN       |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |      Angular SOC Reconciliation View     |
                      |   - 6 KPI interactive summary cards      |
                      |   - 24h / 48h / 7d / 30d window selector |
                      |   - Category / Service / Spec filtering  |
                      |   - Provenance & Status distribution     |
                      |   - Inter Regular (400) Wallarm SOC UI   |
                      +------------------------------------------+
```

---

## 3. Canonical Operation Identity & Matching Semantics

### 3.1 Identity Triplet

To guarantee reliable comparison across disparate sources (FastAPI, Spring Boot, Node.js, Express), both wire telemetry and specification paths are converted into a canonical identity:

$$\text{Operation Identity} = (\text{Service Boundary}, \text{Normalized Route Template}, \text{HTTP Method})$$

- **Route Normalization:** Standardized through `RouteNormalizer.normalize(route)`:
  - Preserves declared path parameters: `/api/v1/customers/{customerId}`
  - Normalizes bracket variants: `:customerId`, `<customerId>` $\rightarrow$ `{customerId}`
  - Normalizes raw wire UUIDs, hex IDs, and numeric database IDs into `{id}`
  - Removes trailing slashes, query strings, and fragment anchors.
- **Method Equivalence:** Upper-case standard verbs (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`).

### 3.2 Finding Categories & Deterministic Precedence

Each operation evaluated in the universe $\Omega = \mathcal{O}_{\text{observed}} \cup \mathcal{D}_{\text{declared}}$ is assigned to **exactly one** mutually exclusive category. Category precedence is strictly enforced:

| Precedence | Category | Definition & Verification Rules | SOC Meaning & False-Positive Consideration |
| :---: | :--- | :--- | :--- |
| **1** | `AMBIGUOUS` | Multiple conflicting specifications declare contradictory methods for the route, or route normalization cannot safely resolve conflicts. | Indicates potential multi-version conflict or misconfigured specification tagging. Requires manual review. |
| **2** | `MATCHED` | The normalized route template and HTTP method exist in the active specification AND were observed in gateway wire telemetry within the observation window. | Contract verified. Traffic actively exercises declared interfaces. |
| **3** | `METHOD_MISMATCH` | The normalized route template is declared in the specification, but the observed HTTP method was **not** declared for that route. | Potential verb tunneling, uncataloged HTTP method, or missing spec definition. **Not** proof of vulnerability. |
| **4** | `OBSERVED_UNDOCUMENTED` | Active telemetry was observed on the gateway, but the route template is absent from all active specifications in scope. | Shadow API, internal operational endpoint, or forgotten service route. |
| **5** | `DOCUMENTED_UNOBSERVED` | Declared in the active specification, but zero traffic was recorded in the database within the selected observation window. | Unexercised feature, dormant route, or rare batch job. Does **not** mean the route is decommissioned. |

### 3.3 Disjoint Partitioning Property

For any evaluated scope:

$$\text{totalEvaluated} = \text{matched} + \text{observedUndocumented} + \text{documentedUnobserved} + \text{methodMismatch} + \text{ambiguous}$$

$$\text{coveragePercentage} = \frac{\text{matched}}{\text{totalEvaluated}} \times 100\%$$

No operation is double-counted.

---

## 4. Observation Windowing & Data Retention

The reconciliation engine accepts an explicit `windowHours` parameter:
- **Default:** 24 hours (`windowHours=24`)
- **Allowed Range:** 1 hour minimum to 720 hours (30 days) maximum.
- **Boundary Validation:** Requests with `windowHours < 1` or `windowHours > 720` return HTTP 400 with an RFC 7807 `ProblemDetail` response.
- **Timestamp Tracking:** Every item and composite summary response includes `windowStart` and `windowEnd` timestamps (ISO-8601 UTC) indicating the exact aggregation timeframe.

---

## 5. Security & Authorization

Access to reconciliation endpoints is restricted to SOC personnel:
- Supported Roles: `ROLE_SECURITY_ANALYST` and `ROLE_SECURITY_ADMIN`.
- Restricted Roles: Customer / unprivileged users receive HTTP 403 Forbidden.
- Unauthenticated requests receive HTTP 401 Unauthorized.
- Method-level role enforcement via `@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")`.

---

## 6. REST API Endpoints

### 6.1 `GET /api/v1/security/reconciliation`
Returns a paginated list of reconciled operations with composite summary statistics.

**Query Parameters:**
- `page` (default: 0)
- `size` (default: 20, max: 100)
- `category` (optional enum filter: `MATCHED`, `OBSERVED_UNDOCUMENTED`, `DOCUMENTED_UNOBSERVED`, `METHOD_MISMATCH`, `AMBIGUOUS`)
- `service` (optional service name filter)
- `specId` (optional UUID specification filter)
- `windowHours` (integer: 1–720, default: 24)
- `search` (case-insensitive substring filter on route, operationId, and service)

### 6.2 `GET /api/v1/security/reconciliation/summary`
Returns high-level reconciliation metrics for dashboard KPI cards.

---

## 7. Frontend SOC Implementation

- **Location:** `frontend/src/app/features/api-reconciliation/`
- **Route:** `/api-reconciliation`
- **Navigation:** Integrated into SOC sidebar under API Security with `git-compare` icon.
- **UI Elements:**
  - 6 KPI Stat Cards: Total Evaluated, Matched, Undocumented, Unobserved, Method Mismatch, and Coverage %.
  - Click-to-filter capability on KPI cards for rapid workflow navigation.
  - Multi-select filters for Observation Window (24h, 48h, 7d, 30d), Finding Category, Service Boundary, and Specification Scope.
  - Telemetry Provenance Badging: Method badges (`GET`, `POST`, `PUT`, `DELETE`), category status chips, request counts with HTTP status distribution tags (`2xx`, `4xx`, `5xx`).
  - Deep Navigation Links: Direct links to wire telemetry (`/events`) and OpenAPI specs (`/api-specs`).
  - Design Guidelines: Adheres strictly to SOC Wallarm styling, dark palette (`#0F172A`, `#1E293B`, `#334155`), and Inter Regular (`font-weight: 400`) typography across all text, headers, and KPI displays.

---

## 8. Verification & Test Suite Summary

### 8.1 Backend Tests (`gateway/src/test/java/com/aegis/gateway/reconciliation/`)
- `ApiReconciliationServiceTest` (7 tests):
  - Exact match reconciliation
  - Observed undocumented shadow endpoint identification
  - Documented unobserved endpoint identification
  - Method mismatch detection (route match, verb difference)
  - Ambiguous overlapping specification detection
  - Window validation bounds (rejection of < 1 and > 720)
  - Search and category filtering
- `SecurityReconciliationControllerTest` (8 tests):
  - HTTP 401 unauthenticated access rejection
  - HTTP 403 customer access rejection
  - HTTP 200 security analyst and admin access approval
  - Pagination and finding category filtering
  - Window hours query parameter validation
  - Summary metrics endpoint validation
- **Backend Test Result:** 202 tests run, 0 failures, 0 errors (`BUILD SUCCESS`).

### 8.2 Frontend Tests (`frontend/src/app/features/api-reconciliation/`)
- `api-reconciliation.component.spec.ts` (9 tests):
  - Component lifecycle and initialization
  - KPI summary metrics and data rows rendering
  - Filter state mutations and live reload
  - Observation window switching (24h $\rightarrow$ 168h)
  - Search query live filtering
  - Category and service CSS class mapping
  - Empty state handling
  - RFC 7807 ProblemDetail error banner rendering and retry mechanism
  - Multi-page pagination controls
- `security-api.service.spec.ts`:
  - `getReconciliation` and `getReconciliationSummary` HTTP contract validation
- `sidebar.component.spec.ts`:
  - Navigation registry and sidebar link verification (16 navigation links)
- **Frontend Test Result:** 113 tests executed, 0 failures, 113 passed.
- **Frontend Production Build:** Completed successfully with zero warnings/errors.
