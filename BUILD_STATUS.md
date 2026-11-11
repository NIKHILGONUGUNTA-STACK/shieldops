# Aegis Build Status

## Current Milestone: Phase 7.2.4.2 Complete (Telemetry-Driven Data Leakage Detection & BOLA Correlation)

**Status:** `DATA_LEAKAGE_DETECTION_VERIFIED`
**Last Updated:** 2026-11-11
**Active Git Branch:** `main`
**Git Working Tree:** Clean
**Remote Upstream:** `origin/main` (`https://github.com/NIKHILGONUGUNTA-STACK/shieldops.git`)

---

## 1. Automated Build & Test Status

### 1.1 Backend Platform Services (Maven / Java 25)
- **Build Tool:** Apache Maven 3.9.16 / Java 25.0.1 LTS
- **Overall Status:** **SUCCESS**

| Service Module | Tests Run | Failures | Errors | Skipped | Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `aegis-platform` (Parent POM) | — | — | — | — | **SUCCESS** |
| `customer-service` | 17 | 0 | 0 | 0 | **SUCCESS** |
| `account-service` | 26 | 0 | 0 | 0 | **SUCCESS** |
| `transaction-service` | 28 | 0 | 0 | 0 | **SUCCESS** |
| `gateway` | 270 | 0 | 0 | 0 | **SUCCESS** |
| **Total Backend Platform Tests** | **341** | **0** | **0** | **0** | **BUILD SUCCESS** |

### 1.2 Frontend SOC Dashboard (Angular 18 / TypeScript / Node 22)
- **Framework & Tooling:** Angular 18.2.21 / Node.js 22.20.0 / npm 10.9.3
- **Test Runner:** Karma 6.4 / Jasmine 5.2 / ChromeHeadless
- **Production Build:** `dist/aegis-frontend` (375.51 kB initial bundle, 103.55 kB transfer, 0 warnings, 0 errors, build time: 43.193s)

| Test Suite | Spec File | Tests Run | Failures | Status |
| :--- | :--- | :---: | :---: | :--- |
| **App Shell** | `app.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Navbar & Search Bar** | `navbar.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Sidebar & Nav Registry** | `sidebar.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Security API Service** | `security-api.service.spec.ts` | 32 | 0 | **SUCCESS** |
| **Auth Service** | `auth.service.spec.ts` | 3 | 0 | **SUCCESS** |
| **Auth Guard** | `auth.guard.spec.ts` | 3 | 0 | **SUCCESS** |
| **Overview Component** | `overview.component.spec.ts` | 4 | 0 | **SUCCESS** |
| **Badge Components** | `badge.component.spec.ts` | 1 | 0 | **SUCCESS** |
| **Incidents Queue** | `incidents-list.component.spec.ts` | 5 | 0 | **SUCCESS** |
| **Incident Detail** | `incident-detail.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Event Explorer** | `events.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Attack Activity** | `attacks.component.spec.ts` | 3 | 0 | **SUCCESS** |
| **Attack Campaigns** | `campaigns.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Evidence Explorer** | `evidence.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Detection Rules** | `detection-rules.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **BOLA Detection** | `bola-detection.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Policy Decisions** | `policy-decisions.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Audit History** | `audit-history.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **System Health** | `system-health.component.spec.ts` | 2 | 0 | **SUCCESS** |
| **Observed API Inventory** | `api-inventory.component.spec.ts` | 8 | 0 | **SUCCESS** |
| **API Specifications & Operations** | `api-specs.component.spec.ts` | 11 | 0 | **SUCCESS** |
| **Documented vs Observed API Reconciliation** | `api-reconciliation.component.spec.ts` | 12 | 0 | **SUCCESS** |
| **API Security Posture Assessment** | `api-posture.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Settings Component** | `settings.component.spec.ts` | 3 | 0 | **SUCCESS** |
| **Currency Service (Phase 7.2.3.4)** | `currency.service.spec.ts` | 23 | 0 | **SUCCESS** |
| **Financial Amount Component (Phase 7.2.3.4)** | `financial-amount.component.spec.ts` | 6 | 0 | **SUCCESS** |
| **Financial Portfolio Explorer (Phase 7.2.3.4)** | `financial-portfolio.component.spec.ts` | 4 | 0 | **SUCCESS** |
| **Sensitive Data Inventory (Phase 7.2.4.1)** | `sensitive-data.component.spec.ts` | 4 | 0 | **SUCCESS** |
| **Data Leakage & BOLA Detection (Phase 7.2.4.2)** | `data-leakage.component.spec.ts` | 4 | 0 | **SUCCESS** |
| **Total Frontend Tests** | — | **177** | **0** | **BUILD SUCCESS** |

### 1.3 Python Simulation Test Suite (pytest / pytest-asyncio / respx)
- **Framework & Tooling:** Python 3.14.0 / pytest 9.2.0 / pytest-asyncio 1.4.1 / respx 0.23.1
- **Mocking:** 100% offline isolated mocking (respx & MockTransport)

| Test Module | Focus Area | Tests Run | Failures | Status |
| :--- | :--- | :---: | :---: | :--- |
| `test_config.py` | Pydantic v2 configuration, local-only safeguards, env parsing, explicit credentials | 8 | 0 | **SUCCESS** |
| `test_auth.py` | Keycloak Direct Access Grants, token cache, refresh, masking | 7 | 0 | **SUCCESS** |
| `test_gateway_client.py` | Async HTTPX, correlation ID, safe retries, IP safety | 8 | 0 | **SUCCESS** |
| `test_scenario_models.py` | Scenario models, registry categories, reporter redaction | 6 | 0 | **SUCCESS** |
| `test_cli.py` | Typer CLI commands (version, validate, scenarios, doctor) | 6 | 0 | **SUCCESS** |
| `test_benign_customer_flow.py` | SCEN-BENIGN-01 journey, preflight, dry-run invariants, Decimal balance, SOC multi-page pagination & reconciliation summary | 14 | 0 | **SUCCESS** |
| `test_currency.py` (Phase 7.2.3.4) | Indian digit grouping (`en-IN`), fixed demonstration rates (84.00 USD, 108.50 GBP), precision rounding, dual presentation | 18 | 0 | **SUCCESS** |
| `test_data_leakage_scenarios.py` (Phase 7.2.4.2) | 7 labelled scenarios, confusion matrix, precision/recall/F1 metrics, markdown benchmarks | 7 | 0 | **SUCCESS** |
| **Total Python Simulation Tests** | — | **74** | **0** | **BUILD SUCCESS** |

---

## 2. Containerized Runtime Environment & Live Integration Status

### 2.1 Verification Mode Distinction
- **Offline Mocked Verification:** **100% SUCCESS**
  - Backend Platform Services: 315 tests passing (`mvn test`).
  - Frontend Angular SOC Dashboard: 169 tests passing (`ng test --watch=false`).
  - Python Simulation Framework: 67 tests passing (`pytest simulation/tests`).
- **Live Local Integration Status:** **RUNTIME ALIGNED & SOC VERIFIED (`READY_FOR_DATA_LEAKAGE_SIMULATION`)**
  - Verification Report: `docs/phase-7-2-3-7-runtime-soc-integration-verification.md`.
  - Live Journey Report: `docs/phase-7-2-3-6-live-benign-journey.md`.
  - Safety Gate Audit: `docs/phase-7-2-3-5-live-transaction-safety-gate.md`.
  - Gateway Rebuild: `aegis-gateway:latest` aligned with source (`sha256:7cd989396b90ac5debe068f21569ed1bd6482d1b70317dfb08571bb6df4cd054`).
  - Container State: Recreated and healthy via `docker compose up -d --no-deps gateway`.
  - Volume Preservation: `postgres-data` and `redis-data` 100% preserved; zero database migrations or seeders re-run.
  - Financial Ledger Audit: Alex source balance remains **`$12,358.74 USD`**, Sam destination balance remains **`£5,300.25 GBP`**.
  - Benign Evidence Retrievability: **15/15** correlation IDs and transaction `5a9be0d7-b99a-4922-b66b-4a04b40e7d24` confirmed intact with 0 duplicate debits.
  - SOC Endpoint Matrix: 10/10 endpoints responding `200 OK` for Analyst, `401` for Unauth, `403` for Customer.
  - Posture & Reconciliation: Posture reports 38 assessed endpoints with `confirmedVulnerability == false`; Reconciliation reports 24 evaluated discrepancy items.

| Container Name | Service | Local Port | Health Check | Current State |
| :--- | :--- | :--- | :--- | :--- |
| `aegis-gateway-1` | Gateway + Threat Detection & SOC Backend APIs | `127.0.0.1:8000` | `/actuator/health/readiness` | **Healthy (Up, Aligned)** |
| `aegis-postgres-1` | PostgreSQL 17 (Flyway V1–V6) | `127.0.0.1:5433->5432` | `pg_isready` | **Healthy (Up, Preserved)** |
| `aegis-redis-1` | Redis 7 (Stream + Sliding Window) | `127.0.0.1:6379->6379` | `redis-cli ping` | **Healthy (Up, Preserved)** |
| `aegis-keycloak-1` | Keycloak 26 | `127.0.0.1:8080`, `9000` | Port 9000 probe | **Healthy (Up)** |
| `aegis-customer-service-1` | Customer API | `127.0.0.1:8081` | `/actuator/health/readiness` | **Healthy (Up)** |
| `aegis-account-service-1` | Account API | `127.0.0.1:8082` | `/actuator/health/readiness` | **Healthy (Up)** |
| `aegis-transaction-service-1` | Transaction API | `127.0.0.1:8083` | `/actuator/health/readiness` | **Healthy (Up)** |
| `aegis-prometheus-1` | Prometheus 2.54 | `127.0.0.1:9090` | `/healthy` probe | **Healthy (Up)** |
| `aegis-grafana-1` | Grafana 11.2 | `127.0.0.1:3000` | `/api/health` | **Up** |

---

## 3. Phase 5.3 Deliverables Checklist (Angular SOC Dashboard Foundation)

- [x] **Angular 18 Project Foundation:**
  - Modern standalone component architecture with Angular Router and HttpClient.
  - Strict typing, reactive signals, and Node `>=22 <23` engine compatibility in `frontend/package.json`.
- [x] **Cyber SOC Design System & Reusable Design Tokens (`src/styles.css`):**
  - Dark navy / slate surfaces (`#090d16`, `#0f172a`, `#141e33`), tactical teal accents (`#14b8a6`), semantic severity tokens (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and status chips (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`).
  - Dense monospace telemetry data tables and accessible focus states.
- [x] **Responsive Shell & Navigation:**
  - Top `NavbarComponent` with brand shield, engine status (`ADVISORY MODE`), active user role badge (`ANALYST` / `SEC-ADMIN`), and session logout.
  - Left `SidebarComponent` with Command & Control navigation, correlation engine status indicators (`RULE-BOLA-01` to `RULE-INJ-01`), and PostgreSQL V3 health pill.
- [x] **Keycloak OIDC Authentication with PKCE (S256):**
  - Integrated `keycloak-js` utilizing Authorization Code Flow with PKCE (`S256`) against realm `aegis-dev` and public client `aegis-frontend`. Zero client secrets embedded in browser.
  - Functional `authGuard` enforcing authentication and role requirements (`SECURITY_ANALYST` / `SECURITY_ADMIN`).
  - Functional `authInterceptor` securely injecting Bearer tokens into `/api/v1/security/**` requests without token leakage.
  - Local test role simulator on `/login` supporting headless verification.
- [x] **Typed API Integration Layer (`SecurityApiService`):**
  - Strongly typed models matching all 10 Phase 5.2 backend DTO contracts.
  - Full RFC 7807 `ProblemDetail` error handling and configurable base URL (`environment.ts`).
- [x] **Live API-Backed Situational Awareness Dashboard (`OverviewComponent`):**
  - Connected to live `GET /api/v1/security/overview?windowHours={windowHours}`.
  - Dense KPI strip: Evaluated Events, Flagged Anomalies, Open Incidents, and Anomaly Ratio.
  - Severity breakdown bar visualization and Threat Category distribution chips.
  - Top Correlation Rules trigger summary and recent incidents table with links to incident detail.
  - Configurable time window selector (6h, 12h, 24h, 48h, 72h, 168h) with auto-reload.
  - Visible loading, empty, and RFC 7807 error panels. Zero fabricated metrics.
- [x] **Route Placeholders:**
  - Route shells for `/events`, `/incidents`, and `/incidents/:id`.
- [x] **Verification & Regression Checks:**
  - 19 frontend unit tests passing in ChromeHeadless (`TOTAL: 19 SUCCESS`).
  - Production build successful with zero warnings (`dist/aegis-frontend`).
  - 150 backend platform tests passing (`mvn test`).
  - Phase 5.2 live verification gate passing (28 / 28 tests).

---

## 4. Phase 5.4 Deliverables Checklist (Incident Triage, Investigation & Event Explorer)

- [x] **Incident Triage Queue (`/incidents`):**
  - Connected to live `GET /api/v1/security/incidents`.
  - Server-side pagination (`page`, `size`) and column sorting (`sortBy`, `sortDirection`).
  - Multi-attribute filters: status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`), severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and threat category (`BOLA`, `BFLA`, `INJECTION`, `RATE_LIMIT_ABUSE`, `RECONNAISSANCE`, `DATA_EXFILTRATION`, `MULTI_VECTOR_CAMPAIGN`).
  - Bi-directional URL query parameter synchronization (`?status=...&severity=...&page=...`).
  - Resilient states: loading indicators, empty states, and RFC 7807 error alert panels with retry capability.
  - Accessible, compact SOC table with row navigation to `/incidents/:id`.
  - Zero hardcoded incident records.
- [x] **Forensic Incident Investigation Workspace (`/incidents/:id`):**
  - Concurrently queries `GET /api/v1/security/incidents/{id}`, `/evidence`, `/history`, and `/policy-decisions`.
  - Identity banner: incident ID, title, status, severity badge, threat category, timestamps.
  - Empirical Bayesian heuristic confidence score bar with explicit non-probabilistic documentation.
  - Contributing evidence list with detector rule IDs and contributing event chips navigating to `/events?correlationId=...`.
  - Chronological audit lifecycle timeline with timestamps, authenticated actors, previous status, target status, and analyst transition rationales.
  - Advisory policy decisions displaying non-blocking `LOG_ALERT` rationales.
  - Resilient error handling for missing incidents (HTTP 404) and partial API failures.
- [x] **Analyst Status Transition Modal (`PATCH /api/v1/security/incidents/{id}/status`):**
  - Authoritative backend state machine target status selection.
  - Terminal status reopen protection: reopening `RESOLVED` or `FALSE_POSITIVE` requires `ROLE_SECURITY_ADMIN`. UI checks `auth.isSecurityAdmin()` and disables unauthorized reopen attempts.
  - Mandatory 5–512 character reason validation matching backend rules.
  - Interactive confirmation dialog, pending states, error/conflict handling (HTTP 409), and automatic detail/audit refresh on success.
  - Strict preservation of advisory invariant (no automatic blocking, throttling, or credential revocation).
- [x] **API Event Explorer (`/events`):**
  - Connected to live `GET /api/v1/security/events` and `GET /api/v1/security/events/{id}`.
  - Server-side filtering by HTTP status, HTTP method, customer ID, source IP, anomaly indicators, and correlation ID.
  - Server-side pagination with page size controls.
  - Slide-in event inspection drawer for inspecting headers, request URI, client IP, anomaly flags, and correlation metadata.
  - Direct contextual navigation between events and incident queue. Zero fabricated links.
- [x] **Automated Test Suites & Production Build:**
  - 36 automated unit tests passing across all components, guards, and services (`TOTAL: 36 SUCCESS`).
  - Production build completed with 0 errors and 0 warnings (raw bundle 329.6 kB, gzipped 91.16 kB).
  - 150 backend platform tests passing (`mvn test`).
  - 28/28 live verification gate passing (`verify-phase5-api.ps1`).

---

## 5. Phase 5.5 Deliverables Checklist (Wallarm-Inspired SOC UI, Design Tokens & Feature Navigation)

- [x] **Visual Reference Analysis & Design System Calibration (`docs/phase-5-ui-design-spec.md`):**
  - Sampled and implemented Wallarm-inspired dark matte palette: canvas (`#0b0d13`), card surfaces (`#141722`), warm amber accents (`#f97316`), tactical teal (`#14b8a6`), violet (`#818cf8`), and cyan (`#06b6d4`).
  - Centralized design tokens in `src/styles.css` including pill control groups, stat badges, planned banners, and accessible focus outlines.
  - Documented `Inter` typography investigation, geometric UI scale, and `JetBrains Mono` monospace fallback hierarchy.
- [x] **Persistent Collapsible Navigation Rail (`SidebarComponent`):**
  - Exact 5 operational groups: `DASHBOARD`, `ATTACKS & INVESTIGATION`, `API SECURITY`, `DETECTION & RESPONSE`, `GOVERNANCE & OPERATIONS`.
  - 15 total navigation destinations with crisp SVG icons, route-active indicators, and accessible labels.
  - Desktop collapse/expand toggle (`240px` $\leftrightarrow$ `64px`) with tooltips.
  - Mobile off-canvas drawer with backdrop overlay.
  - Permanent `ADVISORY MODE` indicator and gateway version tag.
- [x] **Wallarm-Inspired Header & Command Bar (`NavbarComponent`):**
  - Brand shield: `🛡️ AEGIS SOC` with `ACTIVE RECON` pill.
  - Center global search bar (`Search telemetry, incidents, events... ⌘K`) routing directly to correlation searches.
  - Center-right pulsing `ENGINE: ADVISORY MODE` indicator.
  - User profile card with avatar initials, role badge (`SEC-ADMIN` / `ANALYST`), and logout button.
- [x] **Truthful Feature Availability & Complete Route Map:**
  - **Implemented Active Views (13):** Overview, Incidents, Incident Detail, Attacks, Campaigns, Evidence, Events, Data Access, Detection Rules, BOLA Detection, Policy Decisions, Audit History, Settings, System Health.
  - **Planned Capabilities (2):** API Inventory & API Specifications prominently badged with `PLANNED CAPABILITY — Phase 6 Roadmap` architectural previews. Zero fake mock data or simulated security controls.
- [x] **Comprehensive Automated Verification & Zero Build Warnings:**
  - 74 automated unit tests passing across all components, guards, layout services, and API layers (`TOTAL: 74 SUCCESS`).
  - Angular production build completes with 0 errors and 0 warnings (raw bundle 367.7 kB, gzipped 102.1 kB).
  - 150 backend platform tests passing (`mvn test`).

---

## 6. Multi-Phase Progression Path

1. **Phase 2 (Completed):** FinTech foundation with 45 automated tests, service-layer orchestration, RFC 7807 error handling, and verified runtime idempotency.
2. **Phase 3 (Completed):** Established security path (API Gateway routing, Keycloak OIDC/JWT perimeter enforcement, gateway bypass defense, request correlation, and privacy-conscious telemetry capture).
3. **Pre-Phase 4 Hardening (Completed):** 103 automated tests, real `GET /api/v1/security/events` API with server-side RBAC, 20/20 live checks, Prometheus/Grafana observability, concurrent load test harness, and network boundary hardening.
4. **Phase 4.1 (Completed):** Comprehensive Contextual API Threat Detection Architecture, rule taxonomy, data models, processing strategy comparison, and evaluation plan in `docs/phase-4-detection-architecture.md`.
5. **Phase 4.2 (Completed):** First deterministic detection rule `RULE-BOLA-01` implemented end-to-end with Flyway V2, Redis sliding window, dual-group stream consumption, 17 unit/component tests, and live verification gate passing with 100% precision/recall.
6. **Phase 4.3 (Completed):** Contextual Correlation layer implemented on top of `RULE-BOLA-01`, featuring Bayesian confidence combination, multi-resource campaign escalation (`CRITICAL BOLA_CAMPAIGN`), anti-affinity shared IP defense, 128 passing platform tests, and live evaluation benchmark.
7. **Phase 4.4 (Completed):** Multi-Vector Detection and Cross-Rule Correlation (`RULE-AUTH-01`, `RULE-DATA-01`, `RULE-RATE-01`, `RULE-PROBE-01`, `RULE-INJ-01`), `MultiVectorCampaignCorrelator`, 192 platform tests, and expanded 14-scenario evaluation benchmark in `docs/phase-4-multivector-detection.md`.
8. **Phase 5.1 (Completed):** Security Operations API Audit, Gap Analysis, and REST Contract Specification in `docs/phase-5-api-design.md`.
9. **Phase 5.2 (Completed):** Security Operations Backend REST Endpoints, Flyway V3 Indexes, 150 automated platform tests, and 28/28 live verification gate.
10. **Phase 5.3 (Completed):** Angular 18 SOC Dashboard Foundation, Keycloak PKCE Authentication, Design System Tokens, Typed API Service Layer, and Live Overview Dashboard.
11. **Phase 5.4 (Completed):** Interactive Incident Triage Queue, Forensic Investigation Workspace, Analyst Status Transitions, API Event Explorer, 36 unit tests, and production build verification.
12. **Phase 5.5 (Completed):** Final Wallarm-Inspired SOC UI, Design Tokens, Collapsible 15-Destination Sidebar Navigation, Truthful Feature Classification, 74 Unit Tests, and Zero Build Warnings.
13. **Phase 6.1 (Completed):** Telemetry-Based API Discovery Architecture, route normalization, database persistence (`security_data.api_events`), `ApiDiscoveryService`, `SecurityDiscoveryController`, `ApiInventoryComponent` live table and slide-in drawer, 88 frontend unit tests, 168 backend platform tests.
14. **Phase 6.2 (Completed):** Secure OpenAPI Specification Import, offline structural parser supporting OpenAPI 3.0.x / 3.1.x (JSON/YAML), rejection of external references and recursion loops, Flyway V5 schema (`api_specifications` and `api_spec_operations`), `SecuritySpecificationController`, Angular file dropzone, operations exploration drawer, 102 frontend tests, 187 backend platform tests, and zero build warnings.
15. **Phase 6.3 (Completed):** Documented vs. Observed API Reconciliation engine, canonical operation identity normalization (`RouteNormalizer`), deterministic mutually exclusive category precedence (`AMBIGUOUS` > `MATCHED` > `METHOD_MISMATCH` > `OBSERVED_UNDOCUMENTED` > `DOCUMENTED_UNOBSERVED`), observation windowing (1h–720h), composite summary statistics, Angular SOC dashboard (`/api-reconciliation`) with 6 KPI cards, multi-filter dropdowns, deep links to events/specs, 113 frontend tests, 202 gateway tests (273 platform tests total), and zero build warnings.

---

## 7. Phase 6.3 Deliverables Checklist (Documented vs. Observed API Reconciliation)

- [x] **Canonical Operation Identity & Precedence Normalization:**
  - Standardized triplet: `(Service Boundary, Normalized Route Template, HTTP Method)`.
  - Deterministic precedence: `AMBIGUOUS` > `MATCHED` > `METHOD_MISMATCH` > `OBSERVED_UNDOCUMENTED` > `DOCUMENTED_UNOBSERVED`.
  - Disjoint mathematical partitioning: `totalEvaluated == matched + undocumented + unobserved + methodMismatch + ambiguous`. Zero double counting.
- [x] **Backend Reconciliation Repository & Service (`gateway/src/main/java/com/aegis/gateway/reconciliation/`):**
  - Parameterized windowed aggregation on wire telemetry (`security_data.api_events`) with strict 1h–720h window boundaries.
  - Declared OpenAPI operation joining from `security_data.api_spec_operations` and `security_data.api_specifications`.
  - In-memory route normalization, ambiguity detection across multi-spec deployments, composite summary metrics, and pagination.
- [x] **REST API Controller & Authorization:**
  - `GET /api/v1/security/reconciliation` (supports page, size, specId, service, category, windowHours, search).
  - `GET /api/v1/security/reconciliation/summary`.
  - `@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")` role security.
  - RFC 7807 `ProblemDetail` responses for invalid window hours and bad parameters.
- [x] **Frontend SOC View (`/api-reconciliation`):**
  - Standalone `ApiReconciliationComponent` in `frontend/src/app/features/api-reconciliation/`.
  - 6 interactive KPI cards: Total Evaluated, Matched Contracts, Observed Undocumented, Documented Unobserved, Method Mismatch, and Contract Coverage %.
  - Click-to-filter capability on KPI cards.
  - Window selector (24h, 48h, 7d, 30d) with 720h max retention pill indicator.
  - Search input and dropdown filters for Category, Service, and Specification.
  - Table with method badges, category status chips, request counts with HTTP status distributions (`2xx`, `4xx`), and human-readable provenance explanations.
  - Deep action links to wire events (`/events`) and OpenAPI specs (`/api-specs`).
  - Strict Wallarm SOC styling with Inter Regular (`font-weight: 400`) typography.
- [x] **Automated Tests & Production Build:**
  - 15 new backend tests (7 service tests, 8 WebMvcTest controller tests).
  - 202 gateway unit & integration tests passing (`BUILD SUCCESS`).
  - 9 new frontend component unit tests, 2 service tests, 1 sidebar navigation test.
  - 113 frontend tests passing in ChromeHeadless (`TOTAL: 113 SUCCESS`).
  - Production build successful with 0 errors and 0 warnings (`ng build`).

---

## 8. Phase 6.4 Deliverables Checklist (API Discrepancy Prioritization & Forensic Investigation)

- [x] **Deterministic Prioritization Model (`ApiDiscrepancyPrioritizer`):**
  - Rule version `v1.0.0` with transparent 0–100 composite scoring.
  - 4 independent, explainable dimensions: Category Base Risk (0–35), Service Criticality & Sensitive Routes (0–20), Security Telemetry Signals (0–40, 401/403 auth failures & anomaly events), Operational Exposure (0–10), and Temporal Persistence (0–5).
  - Deterministic priority banding: `CRITICAL` (>=75), `HIGH` (50–74), `MEDIUM` (25–49), `LOW` (<25).
  - Separate, orthogonal route matching confidence (`HIGH`, `MEDIUM`, `LOW`) with confidence rationale.
- [x] **Defensive Security Attestation & Provenance Invariant:**
  - Explicit invariant: `confirmedVulnerability: false`.
  - Empirical disclaimer: A discrepancy is an empirical observation of divergence between runtime telemetry and documentation, not proof of exploitability or vulnerability.
  - Missing evidence treated as unknown, not risk.
- [x] **Repository & Service Forensic Dossier Synthesis:**
  - Query extensions: `findDistinctStatusCodesForRoute`, `findLinkedIncidents`, auth failure counts (`status_code IN (401, 403)`), and anomaly flags.
  - `ApiReconciliationService.investigate(...)` synthesizes complete forensic dossier with evidence, OpenAPI context, linked incidents, empirical limitations, and actionable next steps.
  - Priority filtering support on list queries (`GET /api/v1/security/reconciliation?priority=CRITICAL|HIGH|MEDIUM|LOW`).
- [x] **REST API Controller Contracts:**
  - `GET /api/v1/security/reconciliation`: Added optional `priority` parameter with RFC 7807 400 validation.
  - `GET /api/v1/security/reconciliation/{id}`: Dedicated investigation endpoint returning `ReconciliationInvestigationResponse` (200 on success, 404 RFC 7807 when finding absent).
  - Role-based authorization enforced via `@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")`.
- [x] **Angular SOC Forensic Investigation Drawer:**
  - Standalone `ApiReconciliationComponent` enhanced with color-coded priority pills (`prio-critical`, `prio-high`, `prio-medium`, `prio-low`) and numeric score tags.
  - Priority dropdown filter in header controls bar.
  - Interactive slide-out Forensic Investigation Drawer with:
    - Safety Attestation Card (`CONFIRMED VULNERABILITY: NO (DISCREPANCY ONLY)`).
    - Score breakdown showing rule version `v1.0.0` and individual contributing factors with positive score deltas and rationales.
    - Observed telemetry evidence grid (request volume, window duration, 401/403 auth failures, anomaly flags, distinct HTTP status codes).
    - Declared OpenAPI specification metadata and operation details.
    - Linked security incidents and empirical limitations.
    - Prescriptive recommended investigation steps and deep links.
  - Strict Inter Regular (`font-weight: 400`) typography throughout.
- [x] **Comprehensive Test Verification & Production Build:**
  - 25 backend reconciliation tests (6 prioritizer tests, 7 service tests, 12 WebMvcTest controller tests).
  - 212 gateway unit & integration tests passing (`BUILD SUCCESS`).
  - 118 frontend unit tests passing in ChromeHeadless (`TOTAL: 118 SUCCESS`).
  - Angular production build successful with 0 errors and 0 warnings (`ng build`).

---

## 9. Phase 6.5 Deliverables Checklist (API Endpoint Intelligence, Observation History & Specification Evolution)

- [x] **Flyway Migration `V6__api_endpoint_intelligence_and_spec_evolution.sql`:**
  - Added `revision_number INT NOT NULL DEFAULT 1` to `security_data.api_specifications`.
  - Added composite indexes: `api_specs_name_imported_idx`, `api_events_history_idx`, `api_events_status_history_idx`.
- [x] **Unified Endpoint Intelligence Dossier (`GET /api/v1/security/discovery/endpoints/{id}/intelligence`):**
  - Aggregates endpoint identity, service boundary, first/last seen, total request volume.
  - Distinct HTTP status codes array and 2xx/3xx/4xx/5xx count distributions.
  - Latency profiling: average, min, and max latency where available.
  - Declared OpenAPI contract metadata (name, version, revision, path, method, operationId, summary).
  - Reconciliation category, coverage percentage, and discrepancy priority score/factors.
  - Correlated security incidents and defensive safety invariant (`confirmedVulnerability: false`).
- [x] **Continuous Observation History (`GET /api/v1/security/discovery/endpoints/{id}/history`):**
  - Continuous time grid across selectable windows (24h, 168h, 720h) with server-side zero-filling for missing intervals.
  - Explicit retention boundary marker (720h perimeter limit).
  - Interval-level request counts, HTTP status breakdown, and latency metrics.
- [x] **Security Telemetry History (`GET /api/v1/security/discovery/endpoints/{id}/security`):**
  - Total 401/403 authorization failures, anomaly events, and blocked requests.
  - Recent security event log with client IPs, status codes, and anomaly scores.
  - Linked incidents stack.
- [x] **Specification Evolution & Structural Diff Engine:**
  - Auto-incrementing `revision_number` during specification imports.
  - Revision history retrieval (`GET /api/v1/security/specs/{id}/revisions`).
  - Semantic diffing (`GET /api/v1/security/specs/compare?baseId={uuid}&targetId={uuid}`) categorizing operations into `ADDED`, `REMOVED`, `MODIFIED`, and `UNCHANGED` with field-level change details.
- [x] **Angular SOC Dashboard Integration:**
  - Endpoint Intelligence Drawer in `/api-inventory` with Overview, Observation History, and Security tabs.
  - Specification Revision Evolution Drawer and Semantic Diff Explorer in `/api-specs`.
  - Consistent Wallarm SOC dark theme and strict Inter Regular (`font-weight: 400`) typography.
- [x] **Automated Verification:**
  - 10 new backend tests (`ApiEndpointIntelligenceTest`, `SpecificationEvolutionTest`, expanded controller suites).
  - 222 gateway unit & integration tests passing (`BUILD SUCCESS`).
  - 125 frontend unit tests passing in ChromeHeadless (`TOTAL: 125 SUCCESS`).
  - Angular production build successful with 0 errors and 0 warnings (`ng build`).

---

## 10. Phase 7.2.1 Deliverables Checklist (FinTech API Contract Baseline)

- [x] **Authoritative FinTech OpenAPI 3.0.3 Specifications:**
  - `simulation/specs/customer-service.yaml`: 2 declared operations (`getCustomer`, `getCustomerProfile`), role/ownership documentation, RFC 7807 problem details.
  - `simulation/specs/account-service.yaml`: 3 declared operations (`listAccounts`, `getAccount`, `getAccountBalance`), customer summary nesting, balance views. Excluded internal `POST /accounts/{id}/debits` route.
  - `simulation/specs/transaction-service.yaml`: 7 declared operations (`listBeneficiaries`, `createBeneficiary`, `getBeneficiary`, `verifyBeneficiary`, `listTransactions`, `getTransaction`, `executeTransfer`), idempotency headers, transfer validation.
- [x] **Gateway Route Normalization & Service Alignment:**
  - Prefixed routes with `/api/v1` ensuring 100% template alignment with `RouteNormalizer.normalize()`.
  - Service boundary mapping verified with `RouteNormalizer.resolveService()`.
- [x] **Automated Integration & Reconciliation Verification:**
  - `FintechSpecificationBaselineTest.java`: 4 comprehensive integration tests verifying parsing, schema validity, database persistence into `security_data.api_specifications` (3 specs) and `security_data.api_spec_operations` (12 operations).
  - Reconciled against `ApiReconciliationService`: confirmed baseline behavior where all 12 operations start as `DOCUMENTED_UNOBSERVED`.
  - 244 gateway tests passing (`BUILD SUCCESS`, 315 total platform tests).
- [x] **Documentation & Status Synchronization:**
  - Full contract specification in `docs/phase-7-2-1-api-contract-baseline.md`.
  - Updated readiness audit tracking in `docs/phase-7-2-simulation-readiness-audit.md`.

---

## 11. Phase 7.2.2 Deliverables Checklist (Python Simulation Framework Foundation)

- [x] **Modern Project Scaffolding & Packaging:**
  - Created `simulation/pyproject.toml` with dependencies: `httpx>=0.27.0`, `pydantic>=2.7.0`, `typer>=0.12.0`, `rich>=13.7.0`, `pyyaml>=6.0.1`, `python-dotenv>=1.0.1`, `pytest>=8.2.0`, `respx>=0.21.0`.
  - Created `.env.example`, `.gitignore`, `config/default.yaml`, and `simulation/README.md`.
- [x] **Pydantic v2 Configuration & Local-Only Safeguards (`config.py`):**
  - Strict localhost isolation: prohibits non-local target hosts unless `allow_non_local` override is explicitly enabled.
  - Hierarchical loading: env vars -> `.env` file -> YAML config -> model defaults.
  - Zero-leak credential extraction with exclusion from model dumps and string representations.
- [x] **Keycloak Authentication Lifecycle Manager (`auth/keycloak.py`):**
  - Direct Access Grants (`grant_type=password`) with `aegis-dev` realm and `aegis-local` public client.
  - In-memory caching with configurable pre-expiration buffer (`token_expiry_buffer_seconds: 30`) and refresh grant renewal.
  - Multi-identity support and strict `***[REDACTED]***` masking of access tokens.
- [x] **Gateway Async HTTP Client (`clients/gateway.py`):**
  - Async HTTPX client with per-request `X-Correlation-Id` generation, duration measurement in ms, and structured response metadata.
  - Strict bounded retries limited exclusively to safe idempotent methods (`GET`, `HEAD`, `OPTIONS`) on transient 5xx errors.
  - Strictly **no automatic retries** for financial `POST` operations (transfers, beneficiary creation).
  - Synthetic source-IP injection disabled by default (`allow_synthetic_source_ip: false`); rejects arbitrary forwarded headers unless explicitly enabled.
- [x] **Scenario Abstraction & Catalog Registry (`scenarios/` & `models.py`):**
  - `BaseScenario` abstract base class with safe exception trapping and execution summary compilation.
  - Typed models for Scenario Metadata, Categories, Expected Outcomes, Request Results, and Summaries.
  - `ScenarioRegistry` pre-registering 9 standard vector categories (`BENIGN`, `AUTHENTICATION`, `AUTHORIZATION`, `BOLA`, `PROBING`, `INJECTION`, `RATE_ABUSE`, `DATA_ACCESS`, `MULTI_VECTOR`) cleanly marked as `Planned (Phase 7.2.3)`.
- [x] **Leak-Proof Reporting (`reporting/reporter.py`):**
  - Aggregated metrics across runs (requests, status codes, pass/fail counts).
  - Defensive verification rejecting serialization if sensitive tokens or credential strings are detected.
- [x] **Typer & Rich Command Line Interface (`cli.py`):**
  - `aegis-sim version`: framework version.
  - `aegis-sim config validate`: configuration validation and local safeguard verification.
  - `aegis-sim doctor`: non-mutating concurrent diagnostic probes against Gateway, Keycloak, and downstream microservices with ASCII-safe indicators.
  - `aegis-sim scenarios list`: catalog listing of all 9 scenario categories and their implementation status.
- [x] **100% Offline Automated Unit Tests:**
  - 34 automated Python unit tests passing in `8.68s` (7 config, 7 auth, 8 gateway client, 6 scenario models, 6 CLI).
  - All external HTTP interactions mocked with `respx`. Zero external network dependencies.

---

## 12. Phase 7.2.3.1 Deliverables Checklist (First End-to-End Benign FinTech Customer Journey)

- [x] **First Concrete Executable Scenario (`SCEN-BENIGN-01`):**
  - Implemented `BenignCustomerFlow` (`simulation/src/simulation/scenarios/benign_customer_flow.py`) extending `BaseScenario`.
  - Registered in `ScenarioRegistry` (`simulation/src/simulation/scenarios/registry.py`) as implemented (`is_implemented: True`).
  - Realistic multi-step customer journey: Profile discovery, Account listing & balance verification, Beneficiary check & setup (`POST /api/v1/beneficiaries` + `POST /verify`), Transfer initiation (`POST /api/v1/transfers`) with RFC 4122 v4 UUID `Idempotency-Key`, Transaction confirmation (`GET /api/v1/transactions/{id}`), and post-transfer Balance verification.
- [x] **Configurable Business & Safety Rules:**
  - Added `BenignScenarioConfig` in `simulation/src/simulation/config.py` loaded from `config/default.yaml`.
  - Configurable transfer amount ($15.00), transfer currency (USD), source reference (`ACCT-00010001`), and beneficiary reference (`ACCT-00020001`).
  - Strict financial safety: explicit preflight / dry-run mode required (`--dry-run` vs `--execute`); zero unverified financial mutations.
  - No automatic retries on financial mutations (`POST /transfers`, `POST /beneficiaries`).
- [x] **SOC Telemetry & Security Posture Verification:**
  - Implemented `SocTelemetryVerifier` (`simulation/src/simulation/scenarios/soc_verifier.py`).
  - Non-blocking async polling with bounded timeout (`10s`) and jittered backoff.
  - Queries `GET /api/v1/security/discovery/endpoints` and `GET /api/v1/security/posture/endpoints` via Aegis Gateway.
  - Confirms zero incidents generated during benign customer flows (`incident_count == 0`).
  - Confirms endpoint discovery and posture tracking without blocking business execution if SOC APIs are unavailable in offline environments.
- [x] **CLI Execution Runner:**
  - Added `aegis-sim run` command in `simulation/src/simulation/cli.py`.
  - Command usage: `python -m simulation.cli run --scenario SCEN-BENIGN-01 [--dry-run | --execute] [--verify-soc | --no-verify-soc]`.
  - Safety check: blocks execution unless `--dry-run` or `--execute` is explicitly specified.
  - Execution summary manifest saved to `simulation/reports/run-<timestamp>-<scenario>.json` with complete token redaction.
  - Rich console output with structured summary tables and ASCII-safe status indicators.
- [x] **100% Offline Automated Verification:**
  - Created `simulation/tests/test_benign_customer_flow.py` with 7 comprehensive unit tests.
  - Total Python simulation tests: **41 passing in 15.50s**.
  - Backend contract baseline tests: `FintechSpecificationBaselineTest.java` (4 tests passing, 315 total platform tests).
- [x] **Architecture Documentation:**
  - Comprehensive guide in `docs/phase-7-2-3-1-benign-customer-journey.md`.
  - Updated `simulation/README.md` and `docs/phase-7-2-simulation-readiness-audit.md`.

---

## 13. Phase 7.2.3.1.1 Deliverables Checklist (Live Integration Readiness & Correctness Hardening)

- [x] **Zero Fallback Credentials:**
  - Removed hardcoded `Password123!` fallback from `SimulationConfig.get_password()`.
  - Removed dev testbed password dictionary from `load_config()`.
  - Implemented `SimulationConfig.require_password()`: enforces explicit configuration before any business requests, failing fast with descriptive guidance while strictly preventing credential leakage in logs or exceptions.
- [x] **Source Account Preflight Invariants & Schema Validation:**
  - Enforced strict multi-predicate filtering: customer ownership (`customerId == alex_id`), status (`ACTIVE`), currency match (`USD`), and sufficient balance (`balance >= transfer_amount`).
  - Completely removed fallback that selected arbitrary active accounts.
  - Validates `GET /api/v1/accounts/{id}` detail response schema and values.
  - Validates `GET /api/v1/accounts/{id}/balance` response schema (`availableBalance`).
- [x] **Financial Workflow Precision & Decimal Arithmetic:**
  - Used `Decimal` arithmetic for all monetary comparisons and decrement calculations, avoiding IEEE-754 floating-point inaccuracies.
  - Asserted post-transfer balance decreased by exact transfer amount: `post_balance == initial_balance - transfer_amount`.
  - Verified beneficiary verification status: asserts returned status is `VERIFIED`.
  - Preserved financial POST retry prohibition.
- [x] **Genuinely Non-Mutating Dry-Run Mode:**
  - Prohibits fake resource ID generation in dry-run mode (no synthetic UUIDs).
  - Skips mutations (`POST /beneficiaries`, `POST /transfers`, `GET /transactions/{fake_id}`).
  - Emits an explicit list of `planned_mutations` with preflight balance and projected post-transfer balance.
- [x] **Independent Run Traceability & Run Manifest:**
  - Implemented `RunManifest` (`models.py`) containing `run_id`, `scenario_id`, `dry_run`, start/end timestamps, identities used, planned mutations, created resources, and per-request trace records.
  - Added route normalization (`normalize_gateway_route()`) to map wire URLs to declared route templates (e.g. `/api/v1/customers/{id}`).
  - Added `ScenarioReporter.save_manifest()` with automated assertion verifying absence of bearer tokens and credentials.
- [x] **SOC Telemetry & Posture Verifier Hardening:**
  - Distinguishes categorical verification outcomes: `PASS`, `FAIL`, `INCOMPLETE`, and `UNAVAILABLE`.
  - Fixed correlation ID deduplication to prevent inflated verification counts.
  - Run-scoped incident attribution: filters incidents by execution window and verifies correlation ID or entity linkage before attributing to the benign run.
  - Implemented full pagination for `GET /api/v1/security/posture`, inspecting all pages and asserting `confirmedVulnerability == false` across all discovered endpoints.
- [x] **Targeted Automated Tests:**
  - 46 Python simulation tests passing in `31.66s` (100% mocked, zero network dependencies).
  - 4 backend baseline tests passing in `FintechSpecificationBaselineTest.java` (315 total platform tests passing).

---

## 14. Phase 7.2.3.2 Deliverables Checklist (Live Testbed Bring-up & Controlled Integration Readiness)

- [x] **Local Testbed & Infrastructure Inspection:**
  - Verified Docker Compose service topology in `infrastructure/docker/compose.yml` (9 services: postgres, redis, keycloak, customer-service, account-service, transaction-service, gateway, prometheus, grafana).
  - Preserved database volumes (`postgres-data`, `redis-data`).
  - Verified Flyway database seed records for Customer (`customer_data`), Account (`account_data`), Transaction (`transaction_data`), and Gateway (`security_data`).
  - Verified Keycloak realm definition in `keycloak/realm/aegis-dev-realm.json` (`aegis-dev`, public client `aegis-local`, custom mappers for `customerId` and `customerNumber`).
- [x] **Configuration & Isolation Safeguards Validation:**
  - Ran `aegis-sim config validate` verifying all target hosts resolve to `localhost` and business traffic strictly targets Gateway port `8000`.
  - Confirmed microservice direct ports (8081, 8082, 8083) are prohibited from business requests.
  - Confirmed explicit credentials requirement for `alex.morgan`, `sam.taylor`, and `analyst`.
  - Confirmed zero credentials, tokens, or JWTs leaked into logs or version control.
- [x] **Preflight & Live Service Probing:**
  - Executed `aegis-sim doctor`: accurately diagnosed that Docker Desktop Linux daemon (`npipe:////./pipe/dockerDesktopLinuxEngine`) is currently stopped.
  - Executed `aegis-sim run --scenario SCEN-BENIGN-01 --dry-run`: halted safely at Step 0 with descriptive authentication error; zero downstream HTTP calls or mutations dispatched.
- [x] **Financial Safety & Reconciliation Invariants:**
  - Confirmed source account ownership (Alex Morgan, `1000...0001`).
  - Confirmed active status and currency match (USD).
  - Confirmed available balance ($12,500.00) exceeds bounded transfer amount ($25.00).
  - Confirmed destination reference (`ACCT-00020001`) corresponds to Sam Taylor's seed account.
  - Confirmed unique RFC 4122 v4 UUID `Idempotency-Key` and unique transaction reference.
  - Verified that POST operations are non-retryable and reconcile safely upon uncertainty.
- [x] **Authorization Boundary Enforcement:**
  - Prepared exact execution command (`python -m simulation.cli run --scenario SCEN-BENIGN-01 --execute`).
  - Held execution strictly at the boundary (did not invoke `--execute`).
  - Reported exact planned mutations and current blocker (Docker daemon bring-up).
- [x] **Documentation & Architecture Tracking:**
  - Created `docs/phase-7-2-3-2-live-testbed-readiness.md`.
  - Updated `BUILD_STATUS.md` with explicit distinction between offline mocked verification and live integration status.

---

## 15. Phase 7.2.3.3 Deliverables Checklist (Final Transaction Baseline Verification)

- [x] **Source Account Audit & Exact Debit Reconciliation:**
  - Audited Alex Morgan's source account `20000000-0000-4000-8000-000000000001` via Gateway (`GET /api/v1/accounts/{id}/balance`).
  - Confirmed active status, USD currency, and verified current available balance of **`$12,383.74 USD`** (**`₹1,040,234.16 INR`**).
  - Investigated and completely reconciled the `$116.26 USD` (`₹9,765.84 INR`) difference from the original `$12,500.00 USD` seed balance against 20 historical `COMPLETED` transactions in `transaction_data.transactions` (Phase 2, 3, 4 testing).
- [x] **Destination Reference & Outbound Clearing Semantics:**
  - Audited Sam Taylor's destination account `ACCT-00020001` (`20000000-0000-4000-8000-000000000003`) via Gateway (`GET /api/v1/accounts`).
  - Confirmed ownership (Sam Taylor `1000...0002`), active status, and GBP balance (`£5,300.25 GBP` / `₹575,077.13 INR`).
  - Documented that `TransactionService` models outbound wire/ACH instructions: validates `source.currency == beneficiary.currency == transfer.currency == USD` and debits source account without inspecting or crediting the receiver's ledger currency.
- [x] **Beneficiary State Audit:**
  - Retrieved Alex's beneficiary list (`GET /api/v1/beneficiaries`), finding 5 test records but none for `ACCT-00020001`.
  - Confirmed that Step C of `SCEN-BENIGN-01` will execute `POST /api/v1/beneficiaries` and `POST /verify` cleanly during live execution.
- [x] **Transaction Idempotency & Uncertain-Result Safety:**
  - Audited `TransactionService.java` (lines 67–89), confirming that repeated submissions with the identical `Idempotency-Key` return the existing `COMPLETED` record without duplicate debits.
  - Reconfirmed `GatewayClient` prohibition of automatic retries on financial POST operations.
- [x] **Financial Multi-Currency Reporting (Including Rupees ₹):**
  - Added comprehensive INR (₹) representation across all financial baseline metrics and transaction histories.
  - Published findings in `docs/phase-7-2-3-3-transaction-baseline-verification.md`.








