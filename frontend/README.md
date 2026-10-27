# Aegis SOC Dashboard (Phase 5.3 Foundation)

The **Aegis Security Operations Center (SOC) Dashboard** is a high-density, professional web console built with **Angular 18** and modern TypeScript. It consumes real security telemetry, threat correlation incidents, forensic evidence, and advisory policy decisions from the Aegis API Gateway and PostgreSQL backend.

---

## 1. Architecture & Design Direction

- **Framework:** Angular 18 (Standalone Components, Signals, Reactive HttpClient)
- **Styling:** Custom CSS with reusable design tokens (`src/styles.css`), adhering strictly to cybersecurity SOC aesthetics:
  - Dark navy / slate surfaces (`#090d16`, `#0f172a`, `#141e33`)
  - Restrained tactical teal accents (`#14b8a6`)
  - Semantic severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
  - Dense monospace telemetry data tables and status chips
  - Zero external heavy UI libraries (no Tailwind, Bootstrap, or Material)
- **Authentication:** Keycloak OIDC using **Authorization Code Flow with PKCE (S256)** via `keycloak-js`. Client secrets are strictly prohibited from the browser application.
- **API Integration:** Strictly typed service layer (`SecurityApiService`) covering all 10 Phase 5.2 backend endpoints with RFC 7807 `ProblemDetail` error handling.

---

## 2. Directory Layout

```
frontend/src/
├── app/
│   ├── app.component.ts          # Application shell with responsive sidebar/navbar
│   ├── app.routes.ts             # Route definitions with lazy loading & AuthGuard
│   ├── app.config.ts             # Angular providers (HttpClient, AuthInterceptor, Keycloak init)
│   ├── core/
│   │   ├── auth/                 # Keycloak OIDC AuthService, AuthGuard, AuthInterceptor
│   │   ├── models/               # Strongly typed DTO models matching backend contracts
│   │   └── services/             # SecurityApiService (overview, events, incidents, evidence, policies)
│   ├── shared/
│   │   └── components/           # Navbar, Sidebar, SeverityBadge, StatusBadge, Spinner, EmptyState
│   └── features/
│       ├── login/                # SOC Login card with Keycloak OIDC and dev role simulator
│       ├── overview/             # Real API-backed Situation Awareness Dashboard
│       ├── events/               # Event Explorer shell placeholder
│       └── incidents/            # Incident Queue and Forensics placeholders
├── environments/                 # Configurable API & Keycloak URLs
└── styles.css                    # Design system tokens and dark SOC theme
```

---

## 3. Keycloak Authentication Configuration

- **Keycloak Host:** `http://localhost:8080` (or `http://127.0.0.1:8080`)
- **Realm:** `aegis-dev`
- **Client ID:** `aegis-frontend` (Public Client, Standard Flow enabled, Direct Access Grants enabled)
- **PKCE Method:** `S256`
- **Redirect URIs:** `http://localhost:4200/*`, `http://127.0.0.1:4200/*`
- **Web Origins:** `http://localhost:4200`, `http://127.0.0.1:4200`
- **Authorized Test Users:**
  - `analyst` / `Password123!` (`ROLE_SECURITY_ANALYST`)
  - `admin` / `Password123!` (`ROLE_SECURITY_ADMIN`, `ROLE_SECURITY_ANALYST`)

---

## 4. Development & Build Commands

```bash
# Navigate to frontend
cd frontend

# Install dependencies (Node >=22 <23)
npm install

# Run unit tests in headless mode (Karma + ChromeHeadless)
npm test -- --watch=false --browsers=ChromeHeadless

# Build production bundle
npm run build

# Start local development server (http://localhost:4200)
npm start
```

---

## 5. Phase 5.4 Implemented Scope & Workflows

### 5.1 Incident Triage Queue (`/incidents`)
- **Server-Side Pagination & Sorting:** Full pagination controls (`page`, `size`) and column sorting (`sortBy`, `sortDirection`) mapped to backend contracts (`@RequestParam(name = "sortBy")`).
- **Composite Filtering:** Status, severity, and threat category dropdowns synchronized with browser URL query parameters for bookmarkable, shareable search states.
- **Data-Dense SOC Table:** Accessible tabular layout with status/severity badges, detection rule IDs, confidence indicators, and keyboard-navigable rows routing to `/incidents/:id`.
- **Resilient States:** Clear loading spinners, empty search results indicators, and RFC 7807 error alert panels with retry capability.

### 5.2 Incident Investigation Workspace (`/incidents/:id`)
- **Forensic Identity Banner:** Displays incident UUID, title, status, severity badge, threat category, time detected, and last update timestamp.
- **Empirical Bayesian Heuristic Confidence Gauge:** Visual score bar ($0.00 \to 1.00$) explicitly documented as an empirical heuristic metric (not a calibrated statistical probability).
- **Contributing Evidence & Detection Rule IDs:** Lists triggering detector rules, confidence scores, and contributing telemetry event chips with direct navigation to the Event Explorer (`/events?correlationId=...`).
- **Audit Lifecycle Timeline:** Historical chronological audit trail displaying timestamp, authenticated actor, prior status, new status, and analyst transition rationale.
- **Advisory Policy Decisions:** Card-based display of non-blocking security decisions (`LOG_ALERT`), rationale, and rule evaluations preserving the advisory-only architecture.
- **Resilient Error Handling:** Graceful handling for missing IDs (404) and partial API failures without crashing the view.

### 5.3 Analyst Status Transition Workflow (`PATCH /api/v1/security/incidents/:id/status`)
- **Authoritative State Machine:** Target status options strictly mirror backend lifecycle rules (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`).
- **Terminal Reopen Security Enforcement:** Reopening terminal incidents (`RESOLVED` or `FALSE_POSITIVE`) is restricted to users with `ROLE_SECURITY_ADMIN`. The UI checks `auth.isSecurityAdmin()` and disables unauthorized reopen transitions.
- **Reason Validation:** Mandatory 5–512 character reason with real-time character counter and validation matching backend requirements.
- **Transition Dialog:** Clean modal with target status selection, mandatory rationale, confirmation warning, and detailed error handling (including HTTP 409 Conflict handling). Auto-refreshes incident details and audit history on success.
- **Advisory Invariant:** Strictly limited to status transitions. Never triggers automatic blocking, throttling, or credential revocation.

### 5.4 API Event Explorer (`/events`)
- **Server-Side Filtering & Pagination:** Filter by HTTP method, status code, customer ID, source IP, anomaly indicators, and correlation ID.
- **Slide-in Telemetry Inspection Drawer:** Clicking any event row opens a detailed forensic drawer inspecting request URI, headers, timing, client IP, user agent, anomaly flags, and associated correlation ID with quick links to triage.
- **Zero Fabricated Links:** Only navigates to incidents when an actual correlation exists.

### 5.5 Quality & Performance Metrics
- **Unit Tests:** 36 automated unit tests passing in ChromeHeadless (`TOTAL: 36 SUCCESS`).
- **Production Build:** Angular production build (`ng build`) completes with 0 warnings and 0 errors (raw bundle 329.6 kB, gzipped 91.16 kB).
- **Design Tokens:** Strict adherence to custom CSS design tokens in `src/styles.css` without external UI framework overhead.
