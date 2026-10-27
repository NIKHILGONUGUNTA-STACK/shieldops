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

## 5. Phase 5.3 Implemented Scope & Limitations

- **Completed:** Application foundation, design tokens, responsive shell, typed API services, Keycloak PKCE client, route guards, overview page connected to live backend data, unit tests (19/19 passing).
- **Current Limitations:** Full incident triage pagination, status transition modals, and event filtering tables are routed placeholders ready for full component activation in Phase 5.4.
