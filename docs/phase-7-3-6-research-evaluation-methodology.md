# Phase 7.3.6 — Research Evaluation Methodology

**Research Title:** Intrusion Detection and Adaptive Security Response Through API Activity Analysis  
**Project:** ShieldOps (Aegis Security Operations Platform)  
**Repository:** `NIKHILGONUGUNTA-STACK/shieldops`  
**Milestone:** Phase 7.3.6 — Research Evaluation & Experimental Validation  
**Date:** November 2026  

---

## 1. Abstract & Problem Formulation

Modern cloud-native and enterprise architectures rely predominantly on RESTful APIs for inter-service communication and customer interaction. Traditional perimeter defenses, Web Application Firewalls (WAFs), and isolated stateless API gateway security rules inspect individual HTTP requests in isolation. While effective against syntactically identifiable payloads (e.g., SQL injection, cross-site scripting), stateless rule engines are fundamentally incapable of detecting sophisticated logic attacks, such as:

1. **Broken Object Level Authorization (BOLA / IDOR):** Where an authenticated caller retrieves confidential records belonging to another tenant or customer using syntactically valid HTTP GET requests.
2. **Stealthy Low-and-Slow Data Harvesting:** Crawling large sets of records at rates below traditional burst rate-limiting thresholds across extended time horizons.
3. **Distributed Session Scraping:** Token cycling and rotating identities originating from identical network origins or organizational proxies.
4. **Multi-Stage Exfiltration Campaigns:** Coordinated sequences progressing through reconnaissance, authorization boundary probing, sensitive resource discovery, and eventual bulk exfiltration.

**Aegis** introduces a **Contextual API Activity Analysis** architecture that correlates caller identity, tenant boundaries, resource ownership, response data sensitivity classifications, temporal sliding windows, and multi-stage state transitions.

This document formalizes the scientific experimental methodology used to evaluate whether contextual activity analysis provides a statistically defensible and measurable improvement over isolated rule-based detection.

---

## 2. Research Hypothesis

We formulate the primary research hypothesis as follows:

$$\mathcal{H}_1: \text{Contextual API activity analysis achieves a statistically significant improvement in intrusion detection efficacy}$$
$$(\text{higher } F_1\text{-score, lower False Positive Rate, and robust multi-stage campaign correlation}) \text{ over isolated rule-based detection,}$$
$$\text{while maintaining sub-2 millisecond operational latency under an out-of-band advisory architecture.}$$

The corresponding null hypothesis is:

$$\mathcal{H}_0: \text{There is no statistically significant difference in detection efficacy }(F_1\text{-score and FPR})$$
$$\text{between isolated rule-based inspection and contextual activity analysis across identical unlabelled API telemetry.}$$

---

## 3. Experimental Design & Invariants

To eliminate bias and ensure strict scientific reproducibility, the experimental evaluation enforces the following architectural invariants:

### 3.1 Dual-Mode Evaluation on Identical Telemetry
Both detection engines are evaluated against the exact same sequence of API events:
- **Mode A (Isolated Rules Baseline):** Evaluates each HTTP event in isolation without historical state, caller session memory, tenant ownership boundaries, or multi-stage correlation. Rules correspond to industry standard stateless signatures (`RULE-BOLA-01`, `RULE-PROBE-01`, `RULE-DATA-01`).
- **Mode B (Contextual Correlation - Aegis):** Evaluates events with full access to identity anti-affinity, tenant boundaries, resource ownership validation, OpenAPI schema drift tracking, dual sliding-window deques (120s rapid window and 600s low-and-slow window), and multi-stage campaign state machines.

### 3.2 Strict Ground Truth Isolation (Zero Label Leakage)
To prevent construct invalidity and data contamination:
- Ground truth labels (`BENIGN`, `MALICIOUS`, `AMBIGUOUS`, `INCOMPLETE_EVIDENCE`) are generated out-of-band and stored exclusively in a secure verification manifest (`dataset_manifest_v1.json`).
- Detection pipelines ingest strictly normalized wire telemetry (`EventTelemetry`), containing only raw runtime attributes:
  - Event ID, Correlation ID, Timestamp
  - Client IP, Subject / Identity, Tenant ID
  - HTTP Method, Request Path, Status Code
  - Response Size (bytes), Sensitivity Classifications, Latency (ms)
- Ground-truth attributes are stripped prior to ingestion. Neither detector has access to scenario categories, attack indicators, or evaluation unit labels.

### 3.3 Out-of-Band Advisory Safety Architecture
In compliance with enterprise banking and zero-trust invariants:
- Aegis operates strictly asynchronously over Redis Streams telemetry.
- **Zero autonomous actions:** No automated request blocking, throttling, token revocation, identity quarantine, or financial mutations are permitted.
- Detection outputs are emitted as structured, explainable security evidence and advisory incident candidates for human SOC analyst review.
- Telemetry processing does not introduce inline latency to customer transactions (wire latency overhead = 0.00 ms).

---

## 4. Ground Truth Taxonomy & Dataset Stratification

The benchmark dataset (`DS-AEGIS-RESEARCH-V1`) consists of $n = 200$ independently defined scenario executions stratified across four distinct operational categories:

```
                            +-------------------------------------------+
                            | Dataset DS-AEGIS-RESEARCH-V1 (n = 200)   |
                            +-------------------------------------------+
                                                  |
           +--------------------+-----------------+-------------------+--------------------+
           |                    |                                     |                    |
           v                    v                                     v                    v
  +------------------+ +------------------+                 +-------------------+ +-------------------+
  |      BENIGN      | |    MALICIOUS     |                 |     AMBIGUOUS     | |INCOMPLETE EVIDENCE|
  |   80 Scenarios   | |   70 Scenarios   |                 |   30 Scenarios    | |   20 Scenarios    |
  |     (40.0%)      | |     (35.0%)      |                 |      (15.0%)      | |      (10.0%)      |
  +------------------+ +------------------+                 +-------------------+ +-------------------+
  | Normal Banking   | | BOLA Confirmed   |                 | Shared NAT IPs    | | Missing Auth      |
  | Multi-Resource   | | Low-and-Slow     |                 | Role Shifts       | | Dropped Payload   |
  | Safe Pagination  | | Multi-Stage Exfil|                 | Burst Retries     | | Severed Stream    |
  | Concurrent Users | | Schema Drift     |                 | Legitimate Volume | | Truncated Logs    |
  +------------------+ +------------------+                 +-------------------+ +-------------------+
```

1. **Benign Workflows ($n = 80, 40.0\%$):** Legitimate customer journeys including account dashboard viewing, balance queries, authorized multi-resource retrieval, standard pagination browsing, and normal concurrent customer activities.
2. **Malicious Attacks ($n = 70, 35.0\%$):** True attacks covering horizontal IDOR/BOLA cross-customer data retrieval (HTTP 200 on victim resources), stealthy low-and-slow creeping scrapers, rapid burst harvesting, pagination cursor manipulation, and multi-stage exfiltration campaigns.
3. **Ambiguous Contexts ($n = 30, 15.0\%$):** Legitimate operations exhibiting suspicious surface characteristics, such as corporate branch offices sharing a single egress NAT IP, rapid human retry clicks, administrative role transitions, and uncharacteristic volume bursts.
4. **Incomplete Evidence Scenarios ($n = 20, 10.0\%$):** Real-world degraded operational conditions, including dropped authentication context, network timeouts with partial payload captures, truncated proxy logs, and uncatalogued endpoints.

---

## 5. Units of Evaluation

To avoid common research pitfalls where event-level metrics mask campaign failures or scenario-level aggregations distort individual detection accuracy, Aegis evaluates performance across four distinct units:

### 5.1 Scenario-Level (Primary Unit of Evaluation)
The primary unit evaluates whether an entire coherent operational scenario was correctly classified. A scenario is flagged as an alert if the detector emits at least one security finding for that scenario:
- **True Positive (TP):** Malicious scenario correctly flagged.
- **False Positive (FP):** Benign scenario erroneously flagged.
- **True Negative (TN):** Benign scenario cleanly passed without alert.
- **False Negative (FN):** Malicious scenario missed without alert.

### 5.2 Event-Level Evaluation
Evaluates every individual HTTP request and response across the telemetry stream ($N = 640$ total events):
- Measures granular precision and alert volume reduction.
- Assesses whether alert fatigue is minimized in the SOC queue.

### 5.3 Campaign-Level Evaluation
Evaluates whether multi-stage attack progressions are correlated:
- Requires identification of sequential stages: Reconnaissance $\rightarrow$ Authorization Probing $\rightarrow$ Bulk Exfiltration.
- An alert on isolated events that fails to identify the overarching campaign is penalized under campaign recall.

### 5.4 Uncertainty-Handling Evaluation
Evaluates how the system handles the 50 Ambiguous and Incomplete Evidence scenarios:
- A binary system forced to choose `BENIGN` or `MALICIOUS` creates either false positives or dangerous false negatives.
- Contextual correlation introduces an explicit `is_uncertain` flag. Correctly identifying uncertainty routes the incident to Tier-2 SOC triage with an `EVIDENCE_DEGRADED` label.

---

## 6. Statistical Methodology & Metrics Formulation

### 6.1 Performance Metrics
For each evaluation unit, we compute standard confusion matrix metrics:

$$\text{Precision (PPV)} = \frac{TP}{TP + FP}$$

$$\text{Recall (Sensitivity)} = \frac{TP}{TP + FN}$$

$$F_1\text{-Score} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2 \cdot TP}{2 \cdot TP + FP + FN}$$

$$\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$$

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$

$$\text{Specificity (TNR)} = \frac{TN}{TN + FP} = 1 - \text{FPR}$$

### 6.2 Wilson Score Interval for Proportions
For binomial proportions (e.g., Precision, Recall, FPR), normal approximations fail near 0 or 1. We compute asymmetric 95% Wilson score confidence intervals:

$$w = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

where $\hat{p}$ is the sample proportion, $n$ is the sample size, and $z = 1.96$ for $\alpha = 0.05$.

### 6.3 Non-Parametric Bootstrap Confidence Intervals
Because events within a scenario are temporally correlated (violating independent identically distributed assumptions), confidence intervals for $F_1$-score are estimated using **scenario-level block bootstrapping**:
1. Draw $B = 500$ bootstrap resamples of size $n = 200$ with replacement from the set of scenarios.
2. For each resample, re-evaluate $F_1$, Precision, and Recall across the sampled scenario cohort.
3. Compute the empirical 2.5th and 97.5th percentiles to establish the non-parametric 95% Bootstrap Confidence Interval $[F_{1, \text{low}}, F_{1, \text{high}}]$.

Strict non-overlap between the Bootstrap 95% CIs of Isolated Rules and Contextual Correlation establishes rejection of the null hypothesis $\mathcal{H}_0$ at $p < 0.001$.

### 6.4 Zero-Denominator Handling
To ensure numerical stability when evaluating sparse or ablated subsets:
- If $TP + FP = 0$, Precision is formally defined as $1.0$ if $TP = 0$ and $FP = 0$ with no malicious events, or $0.0$ if malicious events were present.
- If $TP + FN = 0$, Recall is defined as $1.0$ (no malicious targets existed).
- If $\text{Precision} + \text{Recall} = 0$, $F_1$ is defined as $0.0$.
- In the UI, unexecuted runs display `NOT EVALUATED` or `INCOMPLETE` rather than misleading `0.0%`.

---

## 7. Controlled Ablation Study Methodology

To quantify the marginal contribution of each contextual intelligence component, we execute an 8-mode controlled ablation study over identical telemetry:

| Mode | Configuration | Purpose |
|---|---|---|
| 1 | `FULL_CONTEXTUAL` | Full Aegis engine (All signals enabled) |
| 2 | `NO_OWNERSHIP` | Disables resource ownership checks (treats all requests as owner-authorized) |
| 3 | `NO_SENSITIVITY` | Disables field-level sensitivity classification and OpenAPI drift detection |
| 4 | `NO_TEMPORAL` | Disables sliding-window deques (120s rapid and 600s low-and-slow) |
| 5 | `NO_AUTH_OUTCOME` | Ignores HTTP status code (treats 403 denied probes identically to 200 successes) |
| 6 | `NO_IDENTITY_AFFINITY` | Disables token-cycling anti-affinity tracking |
| 7 | `NO_STAGE_CORRELATION` | Disables multi-stage campaign state machine progression |
| 8 | `NO_UNCERTAINTY_HANDLING` | Forces binary classification on ambiguous / incomplete evidence |

For each ablated mode $m$, the marginal performance impact is defined as:

$$\Delta F_1(m) = F_1(m) - F_1(\text{FULL\_CONTEXTUAL})$$

The signal with the largest negative $\Delta F_1$ is identified as the most critical architectural component.

---

## 8. Summary of Experimental Rigor

The evaluation framework guarantees:
- **Reproducibility:** Seeded pseudo-random generation yielding identical SHA-256 manifest hash `b8ba6bd4bb22d9ebd0a38a9cd58de601fcbc227f18a55f06ce47f4b86180df18`.
- **Integrity:** Zero leakage between ground-truth labels and detection telemetry.
- **Statistical Validity:** Non-parametric bootstrap resampling at the scenario unit.
- **Traceability:** PostgreSQL schema persistence under Flyway V11 in `security_data`.
- **Operational Reality:** Sub-2ms processing latency with 100% wire decoupling.
