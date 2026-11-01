# Aegis Phase 6.4 — API Discrepancy Prioritization & Forensic Investigation

## 1. Executive Summary

Aegis Phase 6.4 delivers an explainable, deterministic API discrepancy prioritization and forensic investigation workflow that builds directly upon:
- **Phase 6.1**: Telemetry-based runtime discovery (`security_data.api_events`)
- **Phase 6.2**: OpenAPI specification import & validation (`security_data.api_specifications`, `security_data.api_spec_operations`)
- **Phase 6.3**: Strict reconciliation engine (`ApiReconciliationService`, canonical operation identity, precedence matching)

Phase 6.3 establishes whether runtime operations match declared specifications. Phase 6.4 addresses analyst triage overload by evaluating which discrepancies warrant immediate investigation, why they matter, and what empirical evidence supports downstream security analysis.

Crucially, Phase 6.4 is an **investigation and prioritization layer**, not an opaque scoring engine or automated blocking system:
1. **Explainable Determinism**: Bounded 0–100 scoring based on rule version `v1.0.0` with transparent contributing factors and score deltas.
2. **Defensive Security Invariant**: `confirmedVulnerability: false`. An undocumented endpoint or discrepancy is an observation of divergence between runtime telemetry and documentation, not proof of exploitability or vulnerability.
3. **Forensic Evidence Provenance**: Direct linking of gateway telemetry, distinct status codes, authentication failures (401/403), linked security incidents, and empirical limitations.

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
                      |   (401/403 auth failures & anomalies)    |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |        ApiReconciliationRepository       |
                      |   - Telemetry aggregations + auth counts |
                      |   - findDistinctStatusCodesForRoute      |
                      |   - findLinkedIncidents                  |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |        ApiDiscrepancyPrioritizer         |
                      |   - Deterministic rule engine (v1.0.0)   |
                      |   - Factor deltas & transparent rationales|
                      |   - Decoupled matching confidence        |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |         ApiReconciliationService         |
                      |   - Priority filtering & sorting         |
                      |   - Forensic investigation synthesis     |
                      |   - Empirical limitations & actions      |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |    SecurityReconciliationController      |
                      |   - GET /api/v1/security/reconciliation  |
                      |     (?priority=CRITICAL|HIGH|MED|LOW)    |
                      |   - GET /.../reconciliation/{id}         |
                      +------------------------------------------+
                                            |
                                            v
                      +------------------------------------------+
                      |   Angular SOC Reconciliation Component   |
                      |   - Priority badges & score indicators   |
                      |   - Priority dropdown filter             |
                      |   - Forensic Investigation Side Drawer   |
                      |   - Safety Attestation: CONFIRMED: NO    |
                      +------------------------------------------+
```

---

## 3. Prioritization Model & Transparent Scoring Formula (v1.0.0)

### 3.1 Design Principles

- **Deterministic & Bounded**: Composite score $S \in [0, 100]$.
- **Decoupled Dimensions**: Severity, priority, and matching confidence are kept conceptually distinct.
- **No Inferred Risk**: Missing telemetry is treated as unknown, never as risk. Heuristic scores are explicitly identified as rule-based priority, never calibrated probabilities.
- **Mutually Exclusive Bands**:
  - `CRITICAL`: Score $\ge 75$
  - `HIGH`: $50 \le \text{Score} < 75$
  - `MEDIUM`: $25 \le \text{Score} < 49$
  - `LOW`: $\text{Score} < 25$

### 3.2 Scoring Dimensions & Contributing Factors

$$S = \min\left(100, \Delta_{\text{cat}} + \Delta_{\text{srv}} + \Delta_{\text{sec}} + \Delta_{\text{ops}} + \Delta_{\text{temp}}\right)$$

#### 1. Category Base Risk ($\Delta_{\text{cat}} \in [0, 35]$)
Reflects the fundamental nature of the reconciliation finding:
- `OBSERVED_UNDOCUMENTED`: **+30** (Shadow or zombie API absent from OpenAPI specification).
- `METHOD_MISMATCH`: **+20** (Declared route exercising uncataloged HTTP verbs; potential verb tampering).
- `AMBIGUOUS`: **+15** (Conflicting OpenAPI specifications; governance ambiguity).
- `DOCUMENTED_UNOBSERVED`: **+5** (Dormant or unexercised endpoint; minimal immediate exposure).
- `MATCHED`: **0** (Declared and observed in full alignment).

#### 2. Service Criticality & Sensitive Routes ($\Delta_{\text{srv}} \in [0, 20]$)
Based strictly on configured service boundaries and route prefixes:
- High-impact services (`transaction-service`, `auth-service`): **+15**
- Explicit sensitive route patterns (`/admin/`, `/internal/`, `/actuator/`, `/keys`, `/token`): **+10** (capped at +20 total for this dimension)
- Standard services (`customer-service`, `account-service`): **+5**

#### 3. Security Telemetry Signals ($\Delta_{\text{sec}} \in [0, 40]$)
Empirical signals recorded on gateway wire telemetry within the selected observation window:
- Authorization Failures (HTTP 401 Unauthorized / HTTP 403 Forbidden):
  - $\ge 50$ failures: **+30**
  - $10 - 49$ failures: **+20**
  - $1 - 9$ failures: **+10**
- Active Anomaly Flags (`anomaly_events > 0`): **+10**

#### 4. Operational Exposure ($\Delta_{\text{ops}} \in [0, 10]$)
- High Traffic ($\ge 1000$ requests): **+10**
- Moderate Traffic ($100 - 999$ requests): **+5**
- Low Traffic ($1 - 99$ requests): **+2**
- Zero Traffic ($0$ requests): **0**

#### 5. Temporal Persistence ($\Delta_{\text{temp}} \in [0, 5]$)
- Established route observed actively for $\ge 24$ hours: **+5**

### 3.3 Matching Confidence

Matching confidence is computed and reported as an orthogonal metric:
- **`HIGH`**: Direct exact template match or unambiguous undocumented wire observation.
- **`MEDIUM`**: Parameterized template normalization match across variable patterns.
- **`LOW`**: Ambiguous multi-spec collision or conflicting service boundary declarations.

---

## 4. Forensic Investigation Detail View

When an analyst triggers an investigation (`GET /api/v1/security/reconciliation/{id}`), Aegis compiles a forensic dossier:

### 4.1 Safety Attestation & Empirical Limitations
- `confirmedVulnerability: false`
- Explicit disclaimer: *"Scoring reflects empirical runtime telemetry within the selected observation window only. A discrepancy is an observation of divergence between runtime telemetry and documentation, not proof of exploitability or vulnerability."*

### 4.2 Telemetry Evidence Provenance
- Total request volume and status code distribution
- Exact authorization failure count (HTTP 401 / 403)
- Anomaly event counts from gateway monitoring
- Distinct observed HTTP status codes (e.g., `[200, 401, 403]`)
- First and last observation timestamps
- Active observation window boundary (`windowStart`, `windowEnd`, `windowHours`)

### 4.3 Specification Provenance
- Linked OpenAPI specification ID, name, version, and format (`JSON`/`YAML`)
- Declared operation ID, summary, and description
- Declared HTTP methods for the route

### 4.4 Linked Incidents & Recommended Actions
- Linked security incidents matching service boundary or route within the observation window
- Context-aware actionable next steps (e.g., verify shadow endpoints with engineering teams, update OpenAPI contract, investigate 401 spikes).

---

## 5. REST API Contracts

### 5.1 Reconciled Operations List (with Priority Filtering)
`GET /api/v1/security/reconciliation`

**Query Parameters:**
- `priority` (optional): Filter by priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). Returns RFC 7807 400 for invalid values.
- `category` (optional): Filter by discrepancy category.
- `service` (optional): Filter by service boundary.
- `specId` (optional): Filter by specification ID.
- `windowHours` (optional, default `24`): Observation window in hours (1 to 720).
- `search` (optional): Route / operation search string.
- `page` (optional, default `0`), `size` (optional, default `20`).

**Response Item Extensions:**
```json
{
  "id": "rec_f8a92b...",
  "category": "OBSERVED_UNDOCUMENTED",
  "httpMethod": "POST",
  "normalizedRoute": "/api/v1/internal/debug",
  "serviceBoundary": "customer-service",
  "priority": "HIGH",
  "priorityScore": 65,
  "matchingConfidence": "HIGH",
  "authFailureCount": 3,
  "anomalyEventCount": 1,
  "totalRequests": 42
}
```

### 5.2 Forensic Investigation Dossier
`GET /api/v1/security/reconciliation/{id}`

**Query Parameters:**
- `windowHours` (optional, default `24`)
- `from`, `to` (optional)
- `specId` (optional)

**Response Payload (`ReconciliationInvestigationResponse`):**
```json
{
  "findingId": "rec_f8a92b...",
  "category": "OBSERVED_UNDOCUMENTED",
  "categoryDescription": "Active telemetry observed on wire but route is absent from active OpenAPI specifications.",
  "httpMethod": "POST",
  "normalizedRoute": "/api/v1/internal/debug",
  "serviceBoundary": "customer-service",
  "priority": "HIGH",
  "priorityScore": 65,
  "ruleVersion": "v1.0.0",
  "contributingFactors": [
    {
      "factorId": "CATEGORY_BASE",
      "factorName": "Discrepancy Category Base Risk",
      "scoreDelta": 30,
      "rationale": "Observed undocumented route (shadow/zombie API)."
    },
    {
      "factorId": "SECURITY_SIGNALS",
      "factorName": "Security Telemetry Indicators",
      "scoreDelta": 25,
      "rationale": "Detected 3 authorization failures (HTTP 401/403) and 1 anomaly events."
    },
    {
      "factorId": "OPERATIONAL_EXPOSURE",
      "factorName": "Observed Traffic Volume",
      "scoreDelta": 10,
      "rationale": "Observed 42 requests in the current evaluation window."
    }
  ],
  "matchingConfidence": "HIGH",
  "confidenceRationale": "Direct route normalization match with runtime telemetry.",
  "telemetryEvidence": {
    "totalRequests": 42,
    "authFailures": 3,
    "anomalyEvents": 1,
    "distinctStatusCodes": [200, 401, 403],
    "firstObservedAt": "2026-10-28T02:00:00Z",
    "lastObservedAt": "2026-10-29T08:00:00Z",
    "windowStart": "2026-10-28T10:00:00Z",
    "windowEnd": "2026-10-29T10:00:00Z",
    "windowHours": 24,
    "observedMethods": ["POST"]
  },
  "specificationMetadata": null,
  "linkedIncidents": [],
  "empiricalLimitations": [
    "Scoring reflects empirical runtime telemetry within the selected observation window only.",
    "A discrepancy is an observation of divergence between runtime telemetry and documentation, not proof of exploitability or vulnerability."
  ],
  "recommendedActions": [
    "Validate with service team whether this endpoint is an intentional undocumented feature or legacy code.",
    "If legitimate, add the route and operation definition to the OpenAPI contract.",
    "Investigate 3 authorization failures and 1 anomaly events logged for this route."
  ],
  "confirmedVulnerability": false
}
```

---

## 6. Frontend SOC Investigation Drawer

The Angular SOC interface (`ApiReconciliationComponent`) features:
1. **Priority Column & Badges**: Each reconciliation row displays a color-coded priority pill (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) alongside the numeric priority score.
2. **Priority Filtering**: Analysts can filter findings by priority directly from the header controls bar.
3. **Forensic Investigation Drawer**: Clicking `Investigate →` slides open a detailed side panel:
   - **Safety Attestation**: Explicit visual pill (`CONFIRMED VULNERABILITY: NO`) with empirical disclaimer.
   - **Deterministic Score Breakdown**: Shows rule version `v1.0.0`, score progress bar, and list of all contributing factors with score deltas and rationales.
   - **Empirical Telemetry Evidence**: Grid showing request volume, 401/403 auth failures, anomaly flags, and distinct HTTP status codes.
   - **Contract Context**: OpenAPI specification source, declared operation ID, description, and declared HTTP verbs.
   - **Linked Incidents**: Deep links to active security incidents.
   - **Recommended Actions & Limitations**: Prescriptive, defensible guidance for analysts.
4. **Wallarm SOC Inter Regular**: Strict adherence to `font-weight: 400` across all text elements.

---

## 7. Verification & Test Suite Summary

### 7.1 Backend Tests
- **`ApiDiscrepancyPrioritizerTest`** (6 tests):
  - Deterministic bounded scoring (0-100)
  - Category base scores across all finding categories
  - Priority banding (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - Security telemetry factor contributions (401/403 failures, anomalies)
  - Service boundary criticality and sensitive route patterns
  - Decoupled matching confidence
- **`ApiReconciliationServiceTest`** (7 tests):
  - Priority filtering and sorting
  - Complete forensic investigation dossier generation
  - Telemetry evidence and incident aggregation
- **`SecurityReconciliationControllerTest`** (12 tests):
  - Priority query parameter handling (valid and invalid RFC 7807 400)
  - Investigation detail endpoint (`GET /api/v1/security/reconciliation/{id}`) returning 200
  - Investigation 404 for unknown finding ID
  - PreAuthorize access control (`ANALYST`, `ADMIN`, 401 unauthenticated, 403 customer)
- **Gateway Suite Total**: **212 tests run, 0 failures, 0 errors, 1 skipped** (BUILD SUCCESS).

### 7.2 Frontend Tests
- **`security-api.service.spec.ts`**:
  - `getReconciliation` with priority filter parameter
  - `getReconciliationInvestigation` contract verification
- **`api-reconciliation.component.spec.ts`**:
  - Priority badge and score rendering
  - Priority dropdown filter change and data reload
  - Forensic investigation drawer opening, closing, and error states
  - Safety attestation card (`CONFIRMED VULNERABILITY: NO`)
  - Contributing factor breakdown and telemetry evidence verification

