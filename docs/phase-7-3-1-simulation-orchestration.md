# Phase 7.3.1 — Full-Scale Security Simulation and Campaign Orchestration Engine

**Status:** `VERIFIED & PRODUCTION READY`  
**Milestone:** Phase 7.3.1  
**Repository:** `NIKHILGONUGUNTA-STACK/shieldops`  
**Branch:** `main`  
**Verification Date:** November 15, 2026  

---

## 1. Executive Summary & Objective

Phase 7.3.1 elevates the ShieldOps evaluation framework into a full-scale, reproducible security traffic-generation and campaign orchestration platform. The engine continuously generates realistic benign and malicious API traffic against an isolated FinTech testbed. All generated requests traverse the actual API Gateway, telemetry collection pipeline, Redis Streams, PostgreSQL database, detection rules, incident engine, campaign correlator, and policy decision engine.

### Key Architectural Invariants
1. **Zero Fabricated Telemetry:** All simulated events are generated as actual HTTP requests against the gateway loopback (`http://localhost:8000`), never inserted directly into detection or incident databases.
2. **Provenance & Attribution Headers:** Every synthetic request carries explicit attribution headers:
   - `X-Simulation-Run-Id`: Unique execution run identifier (`SIM-RUN-...`).
   - `X-Simulation-Campaign-Id`: Campaign tracking identifier (`SIM-CAMP-...`).
   - `X-Simulation-Scenario-Id`: Specific scenario identifier (`SCEN-...`).
   - `X-Simulation-Stage`: Sequence stage integer.
   - `X-Simulation-Tenant`: Synthetic tenant boundary.
   - `X-Correlation-Id`: Request-level tracing UUID.
3. **Strict Localhost Isolation:** Outbound requests are strictly restricted to `localhost:8000` / `127.0.0.1`. Attempts to target external hosts are intercepted and rejected immediately.
4. **Execution Safety Boundaries:** Maximum duration limits (clamped to 300s), maximum request rate (clamped to 50 req/s), concurrency limits (clamped to 10 workers), and deterministic pseudorandom seeds.
5. **Real-time Lifecycle Controls:** Full support for `START`, `PAUSE`, `RESUME`, and non-blocking `HARD STOP`.

---

## 2. Architecture & Components

```
+--------------------------------------------------------------------------------------------------+
|                                    ShieldOps Platform (Phase 7.3.1)                              |
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|   +------------------------------------+          +------------------------------------------+   |
|   |   Angular SOC Dashboard            |          |   Python Simulation Engine               |   |
|   |   Route: /simulation               |          |   CLI: aegis-sim campaign [list|run]     |   |
|   |   - Campaign Templates             |          |   - CampaignOrchestrator                 |   |
|   |   - Scenario Catalogue (43)        |          |   - Multi-stage Assertion Evaluator      |   |
|   |   - Live Controls (Start/Pause)    |          |   - Async HTTPX with Attribution Headers |   |
|   |   - History & Reports              |          +--------------------+---------------------+   |
|   +-----------------+------------------+                               |                         |
|                     | REST API                                         | HTTP Traffic            |
|                     v                                                  v                         |
|   +--------------------------------------------------------------------+---------------------+   |
|   |                               Gateway Service (localhost:8000)                           |   |
|   |   - SimulationController (/api/v1/simulation/*)                                          |   |
|   |   - SimulationExecutionService (Thread pool, Stage runner, Pause/Stop synchronization)   |   |
|   |   - SimulationCatalogService (43 Scenarios, 5 Templates)                                |   |
|   |   - DefaultSimulationHttpDispatcher (Localhost guardrail & HTTP client)                  |   |
|   +-----------------+------------------------------------------------------------------------+   |
|                     | Telemetry Extraction                                                       |
|                     v                                                                            |
|   +------------------------------------+          +------------------------------------------+   |
|   |   Telemetry Filter & Redis Streams |          |   Detection & Policy Decisions           |   |
|   |   - Attribution Tag Ingestion      | -------> |   - 6 Detection Rules                    |   |
|   |   - Non-Destructive Logging        |          |   - Exfiltration Campaign Correlator     |   |
|   |   - Zero Database Fabrication      |          |   - Adaptive Policy Decision Engine      |   |
|   +------------------------------------+          +------------------------------------------+   |
+--------------------------------------------------------------------------------------------------+
```

---

## 3. Extended Scenario Catalogue (43 Registered Scenarios)

The scenario registry has been expanded from 36 to 43 fully implemented scenarios across 7 functional categories:

| Category | Count | Scenario Highlights |
| :--- | :---: | :--- |
| **BENIGN** | 5 | Normal Customer Workflow (`SCEN-BENIGN-01`), Legitimate Pagination (`SCEN-BENIGN-PAGINATION`), Bulk Export (`SCEN-BENIGN-LARGE-RESP`), Beneficiary Creation (`SCEN-BENIGN-BENEFICIARY`), Lookalike Traffic (`SCEN-BENIGN-LOOKALIKE`) |
| **BOLA** | 3 | Cross-Tenant BOLA (`SCEN-BOLA-01`), Sequential ID Harvest (`SCEN-BOLA-02`), Confirmed BOLA Data Exposure (`SCEN-BOLA-CONFIRMED`) |
| **LEAKAGE** | 2 | Sensitive Data Contract Drift (`SCEN-DATA-LEAK-01`), Restricted Field Exposure (`SCEN-DATA-RESTRICTED`) |
| **EXFILTRATION**| 7 | Unbounded Pagination Scraping (`SCEN-EXTRACT-PAGINATION`), Cumulative Volume (`SCEN-EXTRACT-CUMULATIVE`), Multi-Domain Extraction (`SCEN-EXTRACT-MULTI-RESOURCE`), Recon to Probing (`SCEN-EXFIL-RECON-PROBE`), Probing to Extraction (`SCEN-EXFIL-PROBE-EXTRACT`), Exposure to Bulk (`SCEN-EXFIL-EXPOSE-BULK`), Low-and-Slow Stealth (`SCEN-EXFIL-LOW-SLOW-MULTI`) |
| **PROBING** | 2 | Authentication Abuse & Tampering (`SCEN-SEC-AUTH-ABUSE`), Injection & Fuzzing Probes (`SCEN-SEC-INJECTION-PROBE`) |
| **MIXED** | 22 | Concurrent Benign & Attack (`SCEN-MIXED-CONCURRENT`), Multi-Tenant Boundary (`SCEN-MIXED-MULTI-TENANT`), Window Boundaries (`SCEN-EDGE-WINDOW-BOUNDARY`), Incomplete Sequences (`SCEN-EDGE-INCOMPLETE-SEQUENCE`), Missing Response Size (`SCEN-EDGE-NO-RESP-SIZE`), plus 17 isolated/contextual comparative scenarios |
| **INFRASTRUCTURE**| 2 | Telemetry Stream Backlog Resilience (`SCEN-INFRA-BACKLOG`), Downstream Transient Outage Recovery (`SCEN-INFRA-UNAVAILABLE`) |

---

## 4. Pre-configured Campaign Templates

Five comprehensive, multi-stage campaign templates provide out-of-the-box benchmark workloads:

1. **`TPL-BENIGN-WORKDAY` (Standard Benign Business Workday):**
   - Stage 1: Customer Logins & Profile Fetch (5 iterations, 200ms delay)
   - Stage 2: Transaction History Deep Pagination (4 iterations, 300ms delay)
   - Stage 3: Beneficiary Creation & Verification (3 iterations, 250ms delay)
   - *Expected:* 0 incidents, 0 rule violations, 100% 2xx responses.

2. **`TPL-BOLA-EXFIL-CAMPAIGN` (Full Multi-Stage BOLA Exfiltration Campaign):**
   - Stage 1: Endpoint Reconnaissance & Probing (`SCEN-EXFIL-RECON-PROBE`)
   - Stage 2: Cross-Tenant BOLA Exploitation (`SCEN-BOLA-01`)
   - Stage 3: Confirmed Sensitive Data Leakage (`SCEN-BOLA-CONFIRMED`)
   - Stage 4: Coordinated Bulk Extraction (`SCEN-EXTRACT-PAGINATION`)
   - *Expected:* Alerts on `RULE-BOLA-01`, `RULE-BOLA-CONFIRMED-01`, `RULE-BULK-EXTRACT-01`, Campaign stage transition to `EXTRACTION`, recommended policy `QUARANTINE_IDENTITY`.

3. **`TPL-LOW-SLOW-STEALTH` (Low-and-Slow Stealth Exfiltration Campaign):**
   - Stage 1: Intermittent Account Inquiries (`SCEN-EXFIL-LOW-SLOW-MULTI`, 800ms delay)
   - Stage 2: Cumulative Multi-Tenant Harvesting (`SCEN-EXTRACT-CUMULATIVE`, 900ms delay)
   - *Expected:* Sub-threshold individual calls, cumulative volume threshold trigger, recommended policy `THROTTLE_API_ACCESS`.

4. **`TPL-FULL-MIXED-WORKLOAD` (Mixed Production Traffic & High-Volume Attacks):**
   - Stage 1: Concurrent Mixed Workload (`SCEN-MIXED-CONCURRENT`, 10 iterations)
   - Stage 2: Multi-Tenant Probing with Auth Tampering (`SCEN-SEC-AUTH-ABUSE`, 8 iterations)
   - Stage 3: High-Volume Extraction with Legitimate Traffic (`SCEN-EXTRACT-MULTI-RESOURCE`, 8 iterations)
   - *Expected:* Zero benign false positives, accurate attacker isolation, policy recommendation `BLOCK_IDENTITY`.

5. **`TPL-INFRA-RESILIENCE` (Telemetry Pipeline & Infrastructure Resilience):**
   - Stage 1: Telemetry Stream Backlog Injection (`SCEN-INFRA-BACKLOG`, 15 iterations)
   - Stage 2: Transient Upstream Outage Recovery (`SCEN-INFRA-UNAVAILABLE`, 5 iterations)
   - *Expected:* Telemetry buffer drained without event loss, graceful 503 fallback handling.

---

## 5. Gateway REST API Specification

All endpoints are hosted under `/api/v1/simulation` (and aliased to `/api/v1/security/simulation`), guarded by `hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')`:

- `GET /api/v1/simulation/scenarios`: Returns complete catalogue of 43 simulation scenarios.
- `GET /api/v1/simulation/scenarios/{id}`: Returns scenario metadata and target endpoint contracts.
- `GET /api/v1/simulation/templates`: Returns 5 campaign templates with per-stage assertion rules.
- `GET /api/v1/simulation/templates/{id}`: Returns single template specification.
- `POST /api/v1/simulation/runs`: Launches a new simulation run asynchronously (returns HTTP 201 Created).
- `POST /api/v1/simulation/runs/{runId}/pause`: Atomically suspends ongoing stage execution.
- `POST /api/v1/simulation/runs/{runId}/resume`: Resumes paused worker execution.
- `POST /api/v1/simulation/runs/{runId}/stop`: Executes immediate non-blocking hard stop.
- `GET /api/v1/simulation/runs/{runId}`: Retrieves real-time execution progress, request counters, and stage results.
- `GET /api/v1/simulation/runs`: Retrieves chronological list of active and completed simulation runs.
- `GET /api/v1/simulation/runs/{runId}/report`: Generates downloadable forensic verification report (JSON & Markdown).

---

## 6. Simulation Center SOC Dashboard UI

The Frontend SOC Dashboard incorporates a dedicated **Simulation Center** (`/simulation`) accessible via the sidebar navigation under `GOVERNANCE & OPERATIONS`:

- **Guardrail Banner:** Displays live indicators for local testbed isolation, header provenance, and non-destructive execution mode.
- **KPI Stat Pills:** Engine status (IDLE / RUNNING / PAUSED), total dispatched requests, and refresh trigger.
- **Campaign Templates Tab:** Visual cards displaying traffic mix (`SEQUENTIAL`, `CONCURRENT`, `MIXED`), stage timelines, request rates, and 1-click launch.
- **Scenario Catalogue Tab:** Category filtering (ALL, BENIGN, BOLA, LEAKAGE, EXFILTRATION, PROBING, MIXED, INFRASTRUCTURE), live search, endpoint and outcome chips, and ad-hoc single-scenario execution.
- **Live Execution & Control Tab:** Real-time run ID / campaign ID badges, live action controls (`Pause`, `Resume`, `Hard Stop`), request counters (total, 2xx, 4xx, 5xx), stage pipeline cards with duration metrics, and expected-vs-actual assertion matrix.
- **Execution History & Reports Tab:** Historical run table, status pills, assertion pass rates, and report modal with JSON download and Markdown preview.

---

## 7. Verification & Test Suite Summary

| Layer | Test Suite | Tests Run | Result | Duration |
| :--- | :--- | :---: | :---: | :---: |
| **Python Simulation Framework** | `pytest simulation/tests` | **116** | **0 Failures, 100% Pass** | 47.56s |
| **Backend Gateway Platform** | `SimulationControllerTest` | **5** | **0 Failures, 100% Pass** | 2.46s |
| **Full Backend Test Suite** | `mvn test` (Platform services) | **383** | **0 Failures, 1 Skipped** | ~14s |
| **Frontend SOC Dashboard** | `ng test --watch=false` (Karma/Jasmine) | **198** | **0 Failures, 100% Pass** | 2.81s |
| **Frontend Production Build** | `ng build` (Angular 18) | **1** | **Bundle Complete, 0 Errors** | 31.32s |
| **Simulation CLI Execution** | `aegis-sim campaign run --dry-run` | **2** | **PASS (14 reqs, 3/3 stages)** | 1.8s |

---

## 8. Conclusion

Phase 7.3.1 delivers a robust, reproducible, and non-destructive campaign orchestration engine that bridges synthetic simulation traffic and real SOC telemetry. All assertions and lifecycle operations operate with zero simulated database fabrication, ensuring genuine end-to-end provenance across the ShieldOps platform.
