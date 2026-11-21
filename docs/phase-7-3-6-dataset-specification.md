# Phase 7.3.6 — Dataset Specification: `DS-AEGIS-RESEARCH-V1`

**Dataset Identifier:** `DS-AEGIS-RESEARCH-V1`  
**Version:** `1.0.0`  
**Manifest SHA-256:** `b8ba6bd4bb22d9ebd0a38a9cd58de601fcbc227f18a55f06ce47f4b86180df18`  
**Telemetry File:** `simulation/datasets/dataset_telemetry_v1.json`  
**Manifest File:** `simulation/datasets/dataset_manifest_v1.json`  
**Total Independent Scenarios:** 200  
**Total Normalized Telemetry Events:** 640  
**Generation Seed:** Deterministic PRNG (`seed = 42`)  

---

## 1. Executive Summary & Purpose

Evaluating API security engines requires a dataset that accurately reflects the complexity, ambiguity, and failure modes of real enterprise production environments. Public datasets (such as KDD99 or DARPA) are antiquated, network-layer focused (TCP/IP packets), and lack RESTful API semantic context, identity tokens, JSON payloads, or multi-tenant authorization boundaries.

`DS-AEGIS-RESEARCH-V1` is a scientifically constructed, reproducible evaluation benchmark specifically engineered for API intrusion detection and contextual activity analysis. It models realistic banking microservice operations (Customer, Account, Transfer, Card, and Statement services) under both normal operational workflows and advanced multi-vector attack scenarios.

---

## 2. Dataset Composition & Taxonomy

The dataset contains $n = 200$ independently defined scenario executions stratified across four operational categories:

```
+--------------------------------------------------------------------------------------------------+
|                                  DS-AEGIS-RESEARCH-V1 (n = 200)                                  |
+------------------------------------+------------------------------------+------------------------+
| Category                           | Scenario Count | Scenario Percentage| Event Count (Approx)   |
+------------------------------------+----------------+--------------------+------------------------+
| BENIGN                             | 80             | 40.0%              | 250                    |
| MALICIOUS                          | 70             | 35.0%              | 230                    |
| AMBIGUOUS                          | 30             | 15.0%              | 90                     |
| INCOMPLETE_EVIDENCE                | 20             | 10.0%              | 70                     |
+------------------------------------+----------------+--------------------+------------------------+
| TOTAL                              | 200            | 100.0%             | 640                    |
+------------------------------------+----------------+--------------------+------------------------+
```

---

## 3. Stratified Scenario Breakdown

### 3.1 Benign Workflows ($n = 80$)
These scenarios establish the operational baseline and measure False Positive rates under normal traffic:
- **Single-Resource Customer Reads ($n = 40$):** Authenticated customer querying their own profile (`/api/v1/customers/{id}`), retrieving balances (`/api/v1/accounts/{id}/balance`), or listing cards. All requests match caller identity and customer ownership (`HTTP 200 OK`).
- **Multi-Resource Legitimate Journeys ($n = 15$):** Legitimate user loading an entire dashboard: querying customer details, multiple associated accounts, and recent transactions within a 120-second window. Tests whether the detector erroneously flags multi-resource access when ownership boundaries are respected.
- **Normal Pagination Browsing ($n = 10$):** User browsing transaction history page by page (`page=0, size=20` $\rightarrow$ `page=1, size=20`). Validates that standard UI pagination does not trigger automated scraping alerts.
- **Concurrent Multi-Customer Operations ($n = 10$):** Independent customers accessing their respective resources from distinct IPs and sessions concurrently.
- **Unprivileged Benign Access ($n = 5$):** Standard users accessing public or non-sensitive documentation and health check endpoints.

### 3.2 Malicious Attack Sequences ($n = 70$)
These scenarios evaluate true positive detection, recall, and campaign correlation:
- **BOLA / IDOR Confirmed Leaks ($n = 25$):** Authenticated attacker (`cust-attacker-999`) successfully accesses victim customer profiles or account balances (`HTTP 200 OK`) across tenant boundaries. Represents active data leakage.
- **Horizontal Customer Enumeration / Probing ($n = 15$):** Attacker iterating across customer IDs (`/api/v1/customers/1001`, `1002`, `1003`) encountering access denials (`HTTP 403 Forbidden`). Represents authorization boundary probing.
- **Multi-Stage Exfiltration Campaigns ($n = 10$):** Coordinated sequence progressing through three phases: (1) Reconnaissance, (2) BOLA authorization probing, and (3) Rapid bulk data harvesting. Tests campaign state machine escalation.
- **Low-and-Slow Creeping Extraction ($n = 10$):** Attacker harvesting records at a rate of 1 request every 80 seconds across a 600-second window. Evades standard rapid rate limits (threshold < 3 per 120s), but is captured by Aegis's 600s sliding deque.
- **Rapid Burst Volume Extraction ($n = 5$):** High-velocity automated scrapers extracting $\ge 50,000$ bytes or $\ge 5$ resources in under 60 seconds.
- **Excessive Data Exposure & Schema Drift ($n = 5$):** Exploiting backend endpoints that leak undeclared response fields containing `RESTRICTED` secrets (e.g., social security numbers, unmasked card CVVs) outside the OpenAPI specification.

### 3.3 Ambiguous Operational Contexts ($n = 30$)
Scenarios exhibiting suspicious characteristics that are nonetheless benign:
- **Corporate NAT / Shared Egress IP ($n = 10$):** Multiple distinct authenticated employees sharing a single corporate proxy IP (`198.51.100.42`), accessing different legitimate resources simultaneously. Tests identity anti-affinity to ensure NAT sharing does not trigger distributed scraping alerts.
- **Role Transitions / Administrative Elevations ($n = 10$):** Customer support agents transitioning between customer accounts to assist users during active support sessions.
- **Client-Side Retry Bursts ($n = 5$):** Mobile application encountering temporary network latency and issuing rapid automatic retries (`3 retries in 2 seconds`) for the same idempotent resource.
- **Heavy Legitimate Batch Operations ($n = 5$):** Enterprise corporate customer running legitimate end-of-month reconciliation reports across multiple accounts.

### 3.4 Incomplete Evidence Scenarios ($n = 20$)
Scenarios simulating degraded or lossy operational environments:
- **Missing / Truncated Authentication Tokens ($n = 5$):** Requests where upstream reverse proxies stripped authorization headers or session tokens expired mid-flight.
- **Partial Payload Captures ($n = 5$):** Network stream interruption resulting in truncated response payloads where sensitivity tags cannot be fully evaluated.
- **Severed TCP Streams & Telemetry Loss ($n = 5$):** Redis buffer overflow or network drop resulting in missing intermediate events in a multi-step sequence.
- **Undeclared Routing Paths ($n = 5$):** Legacy uncatalogued microservice routes missing from the OpenAPI baseline inventory.

---

## 4. Ground Truth Isolation & Data Ingestion Schema

To guarantee strict scientific validity, ground-truth metadata is strictly sequestered from the detection pipeline. 

### 4.1 Sequestered Ground Truth (`dataset_manifest_v1.json`)
The manifest stores complete scenario metadata used exclusively by the evaluator:
```json
{
  "scenario_id": "SCEN-MAL-BOLA-01",
  "category": "MALICIOUS",
  "name": "Direct Horizontal Customer BOLA Retrieval",
  "description": "Attacker successfully retrieves victim customer profile with HTTP 200",
  "expected_attack_types": ["BOLA_CONFIRMED_LEAK"],
  "evaluation_unit": "SCENARIO_LEVEL",
  "primary_rule_id": "RULE-BOLA-CONFIRMED-01",
  "target_tenant": "tenant-corp-a",
  "events_count": 2
}
```

### 4.2 Normalized Input Telemetry (`dataset_telemetry_v1.json`)
The telemetry file contains only observable wire attributes:
```json
{
  "event_id": "evt-7a9b1c2d-001",
  "correlation_id": "corr-7a9b1c2d",
  "timestamp": "2026-11-21T12:00:00Z",
  "scenario_id": "SCEN-MAL-BOLA-01",
  "client_ip": "198.51.100.77",
  "subject": "usr-attacker-01",
  "tenant_id": "tenant-corp-a",
  "http_method": "GET",
  "request_path": "/api/v1/customers/cust-victim-001",
  "status_code": 200,
  "response_bytes": 1420,
  "sensitivity_tags": ["CUSTOMER_CONFIDENTIAL", "PII"],
  "latency_ms": 14.2
}
```
*Note: `scenario_id` is retained in the telemetry stream solely as an opaque correlation handle for grouping scenario-level results during post-detection evaluation, identical to a distributed tracing `trace_id`. The detectors do not inspect or parse `scenario_id` for detection logic.*

---

## 5. Manifest Integrity & Verification

The integrity of `DS-AEGIS-RESEARCH-V1` is cryptographically secured via SHA-256:

```
Algorithm: SHA-256
Input: simulation/datasets/dataset_manifest_v1.json
Hash: b8ba6bd4bb22d9ebd0a38a9cd58de601fcbc227f18a55f06ce47f4b86180df18
```

Any alteration to scenario definitions, labels, event counts, or sequence ordering alters this hash and invalidates benchmark comparability.
