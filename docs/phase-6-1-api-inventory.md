# Aegis Phase 6.1 — Telemetry-Based API Discovery Architecture & Implementation

## 1. Executive Summary

Aegis Phase 6.1 introduces passive, telemetry-based API endpoint discovery. Rather than relying on static or manually documented API catalogs, the Aegis Discovery Engine continuously builds and maintains an accurate inventory of live API endpoints observed through real wire traffic passing across the Aegis Gateway perimeter.

Discovery is strictly **read-only** with respect to downstream business applications (`customer-service`, `account-service`, `transaction-service`) and operates without application modifications or external network probes.

---

## 2. Architecture & Data Flow

```
                      +------------------------------------------+
                      |           Inbound Wire Traffic           |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |         Aegis TelemetryFilter            |
                      |   - Captures HTTP method, URI, latency   |
                      |   - RouteNormalizer (sanitizes params)   |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |      security_data.api_events (PG)       |
                      |   - Indexed via V4 method/route index    |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |          ApiDiscoveryRepository          |
                      |   - ANSI SQL GROUP BY method, route      |
                      |   - Status code distribution aggregation |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |          ApiDiscoveryService             |
                      |   - Normalizes and consolidates routes   |
                      |   - Maps downstream service boundaries   |
                      |   - Generates stable endpoint IDs        |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       SecurityDiscoveryController        |
                      |   - GET /api/v1/security/discovery/...   |
                      |   - Role: SECURITY_ANALYST/ADMIN         |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |         Angular SOC Dashboard            |
                      |   - Observed API Inventory UI Table      |
                      |   - Real-time search, filters, pagination|
                      +------------------------------------------+
```

---

## 3. Endpoint Identity & Route Normalization

### 3.1 Endpoint Identity Definition
An observed API endpoint is uniquely identified by the combination of:
1. **HTTP Method:** `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
2. **Normalized Route Template:** E.g., `GET /api/v1/customers/{customerId}/profile`
3. **Service Boundary Identifier:** E.g., `customer-service`
4. **Stable Endpoint ID:** A deterministic identifier generated as `"ep_" + hex_sha256(METHOD + ":" + routeTemplate).substring(0, 16)`.

### 3.2 Normalization Rules
`RouteNormalizer` applies conservative, deterministic transformation:
- **Query String Stripping:** All query parameters (`?customerId=...&token=...`) and URL fragments (`#...`) are completely stripped from endpoint templates to prevent parameter and credential leakage.
- **UUID Normalization:** 36-character standard UUIDs in path positions are mapped to semantic templates:
  - `/customers/{uuid}` -> `/customers/{customerId}`
  - `/customers/{uuid}/profile` -> `/customers/{customerId}/profile`
  - `/accounts/{uuid}` -> `/accounts/{accountId}`
  - `/accounts/{uuid}/balance` -> `/accounts/{accountId}/balance`
  - `/accounts/{uuid}/debit` -> `/accounts/{accountId}/debit`
  - `/beneficiaries/{uuid}/verify` -> `/beneficiaries/{beneficiaryId}/verify`
  - `/transactions/{uuid}` -> `/transactions/{transactionId}`
  - `/security/incidents/{uuid}/evidence` -> `/security/incidents/{incidentId}/evidence`
- **Reference Pattern Normalization:** Prefixed references (`ACCT-*`, `CUST-*`, `SYNTH-*`, `TX-*`) are converted to their respective parameter templates (`{accountId}`, `{customerId}`, `{transactionId}`).
- **Fallback Rule:** Unrecognized UUIDs become `{id}`; unrecognized reference patterns become `{ref}`. Arbitrary path segments without resource context are preserved as literal paths to avoid guessing.

### 3.3 Normalization Limitations & Telemetry Retention Scope
- **Passive Observation Scope:** The inventory reflects only endpoints observed in telemetry within the available PostgreSQL event retention window. Endpoints declared in OpenAPI specs or code that have received zero traffic during the window will not appear in the observed inventory until invoked.
- **Unambiguous Parameter Boundaries:** Fixed endpoints (such as `/api/v1/transfers` or `/actuator/health`) are preserved literally without false parameterization.

---

## 4. Backend API Contract

### 4.1 Endpoints

#### `GET /api/v1/security/discovery/endpoints`
Also aliased to `/security/discovery/endpoints`.

**Security Authorization:** `@PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")`

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | `int` | `0` | 0-indexed page number (≥ 0) |
| `size` | `int` | `20` | Page size (1 to 100) |
| `method` | `string` | optional | Filter by HTTP method (`GET`, `POST`, etc.) |
| `service` | `string` | optional | Filter by service boundary (`customer-service`, etc.) |
| `search` | `string` | optional | Search substring matching route, method, or service |
| `sortBy` | `string` | `lastObserved` | Sort field: `lastObserved`, `totalRequests`, `routeTemplate`, `serviceName`, `firstObserved` |
| `sortDirection` | `string` | `DESC` | `ASC` or `DESC` |

**Response Body (`200 OK`):**
```json
{
  "content": [
    {
      "id": "ep_9e74d3ac268710b1",
      "httpMethod": "GET",
      "routeTemplate": "/api/v1/customers/{customerId}/profile",
      "serviceName": "customer-service",
      "firstObservedAt": "2026-10-28T09:00:00Z",
      "lastObservedAt": "2026-10-28T10:15:00Z",
      "totalRequests": 120,
      "statusDistribution": {
        "2xx": 118,
        "3xx": 0,
        "4xx": 2,
        "5xx": 0
      },
      "distinctStatusCodes": [200, 403],
      "averageLatencyMs": 32.5
    }
  ],
  "page": 0,
  "size": 20,
  "totalElements": 1,
  "totalPages": 1,
  "hasNext": false,
  "hasPrevious": false,
  "totalObservedEndpoints": 1,
  "totalObservedRequests": 120,
  "totalMonitoredServices": 1
}
```

#### `GET /api/v1/security/discovery/endpoints/{id}`
Retrieves a single discovered endpoint record by its stable identifier. Returns `404 Not Found` with RFC 7807 `ProblemDetail` if not found.

---

## 5. Database Schema & Flyway Migration

Flyway migration `V4__api_discovery_indexes.sql`:
```sql
-- 1. Ensure route_id can hold full normalized route templates
ALTER TABLE security_data.api_events 
    ALTER COLUMN route_id TYPE VARCHAR(256);

-- 2. Composite index for endpoint grouping, counting, and discovery queries
CREATE INDEX IF NOT EXISTS api_events_discovery_method_route_idx 
    ON security_data.api_events(http_method, route_id);

-- 3. Composite index for time-windowed discovery queries
CREATE INDEX IF NOT EXISTS api_events_discovery_route_time_idx 
    ON security_data.api_events(route_id, timestamp DESC);
```

---

## 6. Frontend Angular SOC Integration

The planned capability placeholder in `ApiInventoryComponent` is fully replaced with an interactive SOC table view:
- **Aesthetic:** Wallarm-inspired modern dark theme with Inter Regular (`font-weight: 400`) typography throughout.
- **Top Metrics:** Three KPI stat pills displaying live aggregated counts directly from the backend API:
  - Total Observed Endpoints
  - Indexed Telemetry Requests
  - Backend Services
- **Controls Toolbar:**
  - Search input with debounce filter
  - HTTP Method selector
  - Service Boundary selector
  - Manual Refresh button with loading spinner
- **Data Table:**
  - Color-coded HTTP Method badge (GET = Cyan, POST = Green, PUT = Amber, DELETE = Red, PATCH = Purple)
  - Monospace route template with parameters highlighted
  - Service boundary tag
  - Total request count
  - Visual response status breakdown bar (`2xx`, `3xx`, `4xx`, `5xx`) and chip counts
  - First Seen and Last Seen timestamps
- **States:**
  - Loading skeleton table with pulsing placeholders
  - Empty state with guide when no matching traffic is indexed
  - Error state with ProblemDetail details and retry action
  - Server-side pagination controls (Previous, Next, page indicator)
- **Navigation:** Updated `nav-registry.ts` and `sidebar.component.spec.ts` marking API Inventory as `implemented`.
