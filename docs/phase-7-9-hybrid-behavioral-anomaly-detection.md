# Phase 7.9 — Cloudflare-Style Hybrid Behavioral API Anomaly Detection

**Milestone:** Phase 7.9  
**Date:** 2026-11-26  
**Status:** `VERIFIED & PRODUCTION READY`  
**Pattern:** Hybrid Offline Probabilistic Discovery + Runtime Deterministic Zero-Latency Enforcement

---

## 1. Architectural Philosophy & The Latency Paradox

A fundamental challenge in enterprise API security is balancing deep behavioral threat intelligence against strict latency budgets:
- **Synchronous In-Line ML Anti-Pattern:** Inserting heavy probabilistic models (e.g., deep neural networks, complex decision forests) directly into the critical HTTP request-response path introduces unacceptable latency ($50 - 250\text{ ms}$), increases tail latency jitter, and introduces a critical single point of failure.
- **The Cloudflare Hybrid Solution:** Industry leaders such as **Cloudflare (API Shield Sequence Mitigation)**, **Akamai**, and **Salt Security** decouple behavioral discovery from edge enforcement:
  1. **Out-of-Band Analytical Tier:** Learns user journey graphs, transition probabilities, and baseline volumetric profiles asynchronously from historical access logs without touching live traffic.
  2. **Edge Proxy Runtime Tier:** Enforces compiled deterministic workflow state tokens and rolling statistical guards directly in memory ($< 0.1\text{ ms}$), adding **zero noticeable latency** ($0.0\text{ ms}$) to client transactions.

```
                      ┌─────────────────────────────────────────────────────────────┐
                      │                 HOT PATH (ZERO ADDED LATENCY)               │
                      │                                                             │
Client Request ──────►│  Aegis Gateway  ──(Immediate Forward)──► Microservice       │
                      │        │                                        │           │
Client Response◄──────│  Aegis Gateway  ◄──(Immediate Return)─── Microservice       │
                      └────────┼────────────────────────────────────────────────────┘
                               │
                               │  Asynchronous Event Mirror (Fire & Forget via Redis Streams)
                               ▼
                      ┌─────────────────────────────────────────────────────────────┐
                      │              COLD PATH (OUT-OF-BAND ANALYTICS)              │
                      │                                                             │
                      │   Part 1: Markov Sequence Discovery Engine                  │
                      │   Part 3: Streaming Welford Z-Score Outlier Detector        │
                      │                                                             │
                      │   If anomaly confirmed ──► Pushes temporary ban to Redis     │
                      │                            (future requests blocked)        │
                      └─────────────────────────────────────────────────────────────┘
```

---

## 2. The Four Phased Deliverables

Phase 7.9 is implemented across four distinct, independently verifiable parts:

| Phase Part | Domain | Responsibility | Latency Impact |
| :--- | :--- | :--- | :---: |
| **Part 1** | **Background Learning** (`simulation/src/simulation/ml/`) | Unsupervised Markov Chain session traversal engine. Learns transition probability matrices from benign traffic logs, detects out-of-order execution, and extracts critical business funnels. | **0.0 ms** (Runs out-of-band) |
| **Part 2** | **Edge Enforcement** (`gateway`) | Spring Cloud Gateway deterministic workflow verification filter. Enforces prerequisite step completion via in-memory Redis session state and encrypted workflow step tokens. | **< 0.1 ms** (In-memory lookup) |
| **Part 3** | **Streaming Outlier Scoring** (`simulation/src/simulation/ml/` & `gateway`) | Streaming Welford's algorithm computing running mean ($\mu$) and standard deviation ($\sigma$) on payload byte size and processing latency. Flags volumetric exfiltration exceeding $+3.5\sigma$. | **< 0.05 ms** (Two arithmetic ops) |
| **Part 4** | **SOC Dashboard Visualization** (`frontend/src/app/features/`) | Angular 18 Behavioral ML Anomaly Center. Visualizes the Markov journey flow graph, real-time outlier scatter plots, and live anomaly event stream with one-click analyst mitigations. | **0.0 ms** (WebSocket feed) |

---

## 3. Mathematical & Algorithmic Specifications

### 3.1 Part 1: Discrete Markov Chain Traversal Graph

Given a set of declared API operations $S = \{e_1, e_2, \dots, e_M\}$, transitions between consecutive requests in a user session are modeled as a first-order Markov process:

$$P(e_j \mid e_i) = \frac{N(e_i \to e_j) + \epsilon}{\sum_{k=1}^M \left(N(e_i \to e_k) + \epsilon\right)}$$

Where:
- $N(e_i \to e_j)$ is the empirical transition count from endpoint $e_i$ to $e_j$.
- $\epsilon = 10^{-4}$ provides Laplace smoothing for unobserved transitions.

For an observed traversal session $T = (e_1, e_2, \dots, e_K)$, the sequence anomaly score is the normalized negative log-likelihood:

$$S_{\text{seq}}(T) = -\frac{1}{K - 1} \sum_{t=2}^K \ln P(e_t \mid e_{t-1})$$

A session is flagged as a workflow violation if $S_{\text{seq}}(T) > \tau_{\text{seq}}$ (default threshold: $6.0$).

### 3.2 Part 2: Deterministic Workflow State Token Enforcement

From the learned Markov graph, critical business paths (e.g., Funds Transfer, Account Closure) are compiled into deterministic state machine requirements:

$$\text{Prerequisite Table: } e_{\text{target}} \implies \{e_{\text{req}_1}, e_{\text{req}_2}, \dots\}$$

- When a client executes $e_{\text{req}}$, Gateway updates session state in Redis: `session:{sessionId}:steps` with TTL = 300s.
- When $e_{\text{target}}$ is requested, Gateway verifies membership:
  - If verified $\implies$ Request proceeds immediately ($< 0.1\text{ ms}$).
  - If unverified $\implies$ HTTP 403 Forbidden with `ERR_WORKFLOW_VIOLATION`.

### 3.3 Part 3: Streaming Welford's Algorithm for Outliers

To calculate variance without storing historical data points, Welford's algorithm updates running sample mean $\bar{x}_k$ and squared distance sum $M_{2,k}$ iteratively:

$$\bar{x}_k = \bar{x}_{k-1} + \frac{x_k - \bar{x}_{k-1}}{k}$$
$$M_{2,k} = M_{2,k-1} + (x_k - \bar{x}_{k-1})(x_k - \bar{x}_k)$$
$$\sigma_k = \sqrt{\frac{M_{2,k}}{k - 1}}$$

The normalized outlier score for response byte volume and latency is:

$$Z = \frac{x - \bar{x}}{\sigma}$$

If $Z > 3.5$, an asynchronous telemetry anomaly alert is dispatched to Redis Streams.

---

## 4. Implementation Details & Deliverables across All 4 Parts

### 4.1 Part 1: Background Learning — Unsupervised Markov Sequence Engine
- **Files Delivered:**
  - `simulation/src/simulation/ml/models.py`: Pydantic v2 domain schemas (`SequenceStep`, `SessionTrace`, `SequenceProfile`, `TransitionViolation`, `SequenceAnomalyReport`, `OutlierBaselineProfile`, `OutlierEvaluationResult`).
  - `simulation/src/simulation/ml/markov_sequencer.py`:
    - Session trace parser with robust path normalization (`/api/v1/customers/123` $\to$ `/api/v1/customers/{id}`).
    - Laplace-smoothed transition matrix computation ($P(e_j \mid e_i)$ with $\epsilon = 10^{-4}$).
    - Negative log-likelihood sequence anomaly scoring with $6.0$ default threshold.
    - Automated critical business funnel extractor ($\ge 0.50$ transition dependency).
    - JSON profile export/import (`export_profile`, `load_profile`).
  - `simulation/tests/test_markov_sequencer.py`: **7/7 unit tests passing** (0.58s).

### 4.2 Part 2: Edge Enforcement — Zero-Latency Gateway Workflow Filter
- **Files Delivered:**
  - `gateway/src/main/java/com/aegis/gateway/workflow/WorkflowRule.java`: Invariant rule definition linking target endpoints to mandatory predecessors.
  - `gateway/src/main/java/com/aegis/gateway/workflow/WorkflowCheckResult.java`: Outcome record tracking allowed status, violation details, and processing elapsed time ($< 0.1\text{ ms}$).
  - `gateway/src/main/java/com/aegis/gateway/workflow/WorkflowStateService.java`:
    - In-memory Redis session state management with 10-minute sliding TTL (`aegis:workflow:session:{sessionId}:steps`).
    - Local `ConcurrentHashMap` fallback for Redis disconnects or local testing.
    - Endpoint normalization with regex parameter masking (`/{id}`).
    - Security administrator role bypass (`ROLE_SECURITY_ADMIN`).
  - `gateway/src/main/java/com/aegis/gateway/workflow/WorkflowEnforcementFilter.java`:
    - Priority filter registered at `@Order(Ordered.HIGHEST_PRECEDENCE + 45)`.
    - Immediate RFC 7807 problem detail response (`403 Forbidden`, `ERR_WORKFLOW_VIOLATION`) when a skipped-step violation occurs.
  - `gateway/src/main/java/com/aegis/gateway/workflow/WorkflowController.java`:
    - `GET /api/v1/security/workflow/rules`: Declared edge workflow invariants.
    - `GET /api/v1/security/workflow/sessions/{sessionId}`: Real-time executed steps.
    - `POST /api/v1/security/workflow/verify`: Direct deterministic edge verification endpoint.
  - **Tests Delivered:**
    - `gateway/src/test/java/com/aegis/gateway/workflow/WorkflowStateServiceTest.java`: 6/6 tests passing.
    - `gateway/src/test/java/com/aegis/gateway/workflow/WorkflowEnforcementFilterTest.java`: 3/3 tests passing.
    - `gateway/src/test/java/com/aegis/gateway/workflow/WorkflowControllerTest.java`: 3/3 tests passing.

### 4.3 Part 3: Streaming Outlier Scoring — Welford's Algorithm
- **Files Delivered:**
  - `simulation/src/simulation/ml/welford_outlier.py`:
    - `WelfordMetricTracker`: Single-pass $O(1)$ computation of running mean ($\mu$) and sample variance ($\sigma^2$).
    - `StreamingOutlierDetector`: Online $+3.5\sigma$ thresholding for payload bytes and response latency.
  - `gateway/src/main/java/com/aegis/gateway/telemetry/StreamingAnomalyScorer.java`:
    - Thread-safe, zero-lock ConcurrentHashMap endpoint tracker for live API gateway telemetry.
    - Integrated directly into post-response `TelemetryFilter.java` (zero impact on client response latency).
  - **Tests Delivered:**
    - `simulation/tests/test_welford_outlier.py`: 6/6 tests passing.
    - `gateway/src/test/java/com/aegis/gateway/telemetry/StreamingAnomalyScorerTest.java`: 5/5 tests passing.

### 4.4 Part 4: SOC Dashboard Visualization — Angular 18 ML Anomaly Center
- **Files Delivered:**
  - `frontend/src/app/core/services/security-api.service.ts`: Added reactive methods `getWorkflowRules()`, `getWorkflowSessionSteps()`, `verifyWorkflowTransition()`, and `getOutlierStats()`.
  - `frontend/src/app/features/ml-anomalies/ml-anomalies.component.ts`:
    - **Tab 1 (Markov Journey Funnel):** Interactive Markov transition visualization showing critical steps, baseline transition probabilities, and negative log-likelihood metrics.
    - **Tab 2 (Edge Invariants Tester):** Interactive session journey simulator allowing analysts to test benign sequences vs skipped-step attacks with instant sub-millisecond edge verification.
    - **Tab 3 (Streaming Outliers):** Live telemetry table showing running mean ($\mu$), standard deviation ($\sigma$), sample counts, and real-time $+3.5\sigma$ outlier detection flags.
  - `frontend/src/app/features/ml-anomalies/ml-anomalies.component.spec.ts`: 6/6 unit tests passing.
  - `frontend/src/app/app.routes.ts`: Registered route `/ml-anomalies`.
  - `frontend/src/app/core/navigation/nav-registry.ts`: Added navigation link under `DETECTION & RESPONSE` (sidebar count: 23).

---

## 5. Multi-Platform Verification & Quality Gate

| Verification Suite | Platform | Tests Run | Pass Rate | Execution Time |
| :--- | :--- | :---: | :---: | :---: |
| **Python Simulation Framework** | pytest 9.2.0 (Python 3.14) | **177 / 177** | **100%** | 4m 36s |
| **Backend Microservices & Gateway** | Maven 3.9.16 (Java 25) | **488 / 488** | **100%** | 1m 10s |
| - *Customer Service* | Spring Boot 3.5.6 | 24 / 24 | 100% | 12.7s |
| - *Account Service* | Spring Boot 3.5.6 | 26 / 26 | 100% | 10.6s |
| - *Transaction Service* | Spring Boot 3.5.6 | 21 / 21 | 100% | 10.8s |
| - *Aegis Gateway* | Spring Cloud Gateway 2024.0.2 | 417 / 417 | 100% | 35.5s |
| **Frontend SOC Dashboard** | Karma 6.4 / Jasmine 5.2 | **232 / 232** | **100%** | 2.2s |
| **Frontend Production Build** | Angular CLI 18.2.21 | **SUCCESS** | **0 errors, 0 warnings** | 46.7s |
| **Grand Total Platform Tests** | **All Platforms** | **897 / 897** | **100% SUCCESS** | — |
