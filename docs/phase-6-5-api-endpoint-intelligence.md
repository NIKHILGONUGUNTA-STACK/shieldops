# Aegis Phase 6.5 — API Endpoint Intelligence, Observation History & Specification Evolution

## 1. Executive Summary

Aegis Phase 6.5 completes the **API Discovery and Governance** module by delivering a unified endpoint intelligence, historical observation tracking, and specification evolution experience.

Building upon the foundations established in:
- **Phase 6.1**: Telemetry-based runtime discovery (`security_data.api_events`)
- **Phase 6.2**: Secure OpenAPI specification import & validation (`security_data.api_specifications`, `security_data.api_spec_operations`)
- **Phase 6.3**: Strict reconciliation engine (`ApiReconciliationService`, canonical operation identity)
- **Phase 6.4**: API discrepancy prioritization & forensic investigation (`ApiDiscrepancyPrioritizer`, rule version `v1.0.0`)

Phase 6.5 empowers security analysts to select any discovered API endpoint and immediately understand its complete identity, wire telemetry behavior, associated contract, historical observation trends, and specification evolution over time.

---

## 2. Core Architectural Principles & Invariants

1. **Deterministic Endpoint Identity**:
   Every endpoint is keyed by its canonical HTTP method and normalized route template (e.g., `GET /api/v1/customers/{customerId}`). Stable identifiers and deterministic routing hashes prevent duplicate tracking.
2. **Strict Defensive Invariant**:
   `confirmedVulnerability: false`. Discrepancies and shadow routes represent divergence between runtime traffic and declared contracts. They are prioritized operational anomalies, never conflated with confirmed vulnerabilities or active exploits.
3. **Continuous Time-Grid Observation History**:
   Observation history queries generate continuous time intervals across selected windows (24h, 168h, 720h) with server-side zero-filling for missing intervals. Wire telemetry is strictly bounded by the 720-hour perimeter retention limit.
4. **Specification Evolution & Structural Diff**:
   OpenAPI contracts support sequential revisions (`revision_number`). Semantic diffing between revisions categorizes changes into `ADDED`, `REMOVED`, `MODIFIED`, and `UNCHANGED` operations with field-level modification tracking (`tags`, `summary`, `description`, `deprecated`, `operationId`).
5. **Separation of Concerns**:
   No reliance on opaque machine learning, synthetic probes, or automated network disruption. All metrics reflect passive wire telemetry and declared contract definitions.

---

## 3. Database Migration & Schema Extensions

Flyway migration `V6__api_endpoint_intelligence_and_spec_evolution.sql`:
- Added `revision_number INT NOT NULL DEFAULT 1` to `security_data.api_specifications` for tracking version iterations.
- Created `api_specs_name_imported_idx` on `(name, imported_at DESC)` for high-throughput revision lookups.
- Created `api_events_history_idx` on `(http_method, route_id, timestamp DESC)` for fast time-series aggregation.
- Created `api_events_status_history_idx` on `(route_id, status_code, timestamp DESC)` for fast HTTP status distribution aggregation.

---

## 4. REST API Route Contracts

### 4.1 Endpoint Intelligence Dossier
- **Route**: `GET /api/v1/security/discovery/endpoints/{id}/intelligence?windowHours={1..720}`
- **Security**: Requires `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`
- **Payload**:
  - `endpointId`, `httpMethod`, `normalizedRoute`, `serviceBoundary`, `stableHash`
  - `firstObservedAt`, `lastObservedAt`, `totalRequests`
  - `distinctStatusCodes`: Array of HTTP status codes observed (e.g. `[200, 401, 404]`)
  - `statusDistribution`: Mapping of `2xx`, `3xx`, `4xx`, `5xx` counts
  - `averageLatencyMs`, `minLatencyMs`, `maxLatencyMs`
  - `specification`: Declared OpenAPI metadata (`name`, `version`, `revision`, `declaredPath`, `declaredMethod`, `operationId`, `summary`)
  - `reconciliation`: Status category (`MATCHED`, `OBSERVED_UNDOCUMENTED`, etc.) and coverage percentage
  - `discrepancyPrioritization`: Bounded priority score (0–100), level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), primary reason, contributing factors list
  - `relatedIncidents`: Correlated security incidents with client IPs and timestamps
  - `inferredService`: Boolean flag indicating whether service was inferred from route prefix
  - `confirmedVulnerability`: Guaranteed `false`

### 4.2 Endpoint Observation History
- **Route**: `GET /api/v1/security/discovery/endpoints/{id}/history?windowHours={1..720}&bucketMinutes={5..1440}`
- **Security**: Requires `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`
- **Payload**:
  - `windowHours`, `bucketIntervalMinutes`, `totalRequestsInWindow`, `retentionLimitHours: 720`
  - `buckets`: Ordered continuous time intervals with `bucketTimestamp`, `requestCount`, `status2xx`, `status3xx`, `status4xx`, `status5xx`, `avgLatencyMs`, `minLatencyMs`, `maxLatencyMs`

### 4.3 Endpoint Security & Incident History
- **Route**: `GET /api/v1/security/discovery/endpoints/{id}/security?windowHours={1..720}`
- **Security**: Requires `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`
- **Payload**:
  - `totalAuthFailures` (401/403 status counts), `totalAnomalies`, `totalBlocked`
  - `recentSecurityEvents`: Event log (`clientIp`, `statusCode`, `anomalyScore`, `blocked`, `timestamp`)
  - `linkedIncidents`: Incidents correlated by route pattern

### 4.4 Specification Revision History
- **Route**: `GET /api/v1/security/specs/{id}/revisions`
- **Security**: Requires `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`
- **Payload**: Array of all imported revisions of the specification ordered by `revision_number DESC`

### 4.5 Specification Structural Comparison
- **Route**: `GET /api/v1/security/specs/compare?baseId={uuid}&targetId={uuid}`
- **Security**: Requires `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`
- **Payload**:
  - Base and target specification details (`name`, `version`, `revisionNumber`)
  - `addedCount`, `removedCount`, `modifiedCount`, `unchangedCount`
  - `changes`: Array of `OperationChange` objects with `changeType` (`ADDED`, `REMOVED`, `MODIFIED`, `UNCHANGED`) and detailed `fieldChanges` list

---

## 5. SOC Frontend Experience

### 5.1 Endpoint Intelligence Side Drawer (`/api-inventory`)
- Slide-out intelligence drawer on endpoint row click or "Intel" action button.
- **Tab 1: Overview & Contract**:
  - Identity & Telemetry Metrics (Service boundary, inferred status, request volume, min/avg/max latency, timestamps).
  - Distinct HTTP status codes pills and distribution progress bars.
  - Declared OpenAPI contract metadata or shadow API notice.
  - Reconciliation status badge, priority score with level, primary rationale, and contributing factors table.
  - Strict safety attestation: `CONFIRMED VULNERABILITY: NO (DISCREPANCY ONLY)`.
- **Tab 2: Observation History**:
  - Interactive window switching: 24h (Hourly), 7d (4-Hourly), 30d (Daily).
  - Zero-filled continuous timeline table with volume and status distribution chips.
  - Retention limit reminder badge.
- **Tab 3: Security & Incidents**:
  - Security counters (Auth failures, anomaly events, blocked requests).
  - Recent security events log with client IPs, anomaly scores, and block flags.
  - Correlated security incident stack with direct links.

### 5.2 Specification Revision Evolution & Diff Explorer (`/api-specs`)
- Main table displays `Rev X` badge alongside specification version.
- "Revisions" action button opens the Evolution & Diff Drawer:
  - **Revisions Timeline**: Historical iterations of the specification with timestamps, operation counts, content hashes, and "Set as Base" / "Set as Target" shortcuts.
  - **Semantic Revision Diff**: Base vs. Target selectors, summary metric cards (`Added`, `Removed`, `Modified`, `Unchanged`), operation diff list with color-coded change badges, and field-level modification breakdowns.

---

## 6. Verification & Test Coverage Matrix

| Test Suite | Scope | Tests Run | Result |
|---|---|---|---|
| `ApiEndpointIntelligenceTest` | Intelligence compilation & zero-filled time buckets | 5 | PASS (100%) |
| `SpecificationEvolutionTest` | Revision auto-increment & structural diff computation | 5 | PASS (100%) |
| `SecurityDiscoveryControllerTest` | Discovery controller endpoints, RBAC, parameter validation | 11 | PASS (100%) |
| `SecuritySpecificationControllerTest` | Spec upload, revisions endpoint, diff compare, RBAC | 11 | PASS (100%) |
| Frontend Karma Test Suite (`ng test`) | SecurityApiService, ApiInventoryComponent, ApiSpecsComponent | 125 | PASS (100%) |
| Frontend Production Build (`ng build`) | Angular 19 Ahead-of-Time build & bundling | N/A | SUCCESS (0 errors) |
