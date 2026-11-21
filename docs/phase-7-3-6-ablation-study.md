# Phase 7.3.6 — Controlled Ablation Study

**Research Title:** Intrusion Detection and Adaptive Security Response Through API Activity Analysis  
**Project:** ShieldOps (Aegis Security Operations Platform)  
**Evaluation Dataset:** `DS-AEGIS-RESEARCH-V1` ($n = 200$)  
**Milestone:** Phase 7.3.6 — Research Evaluation & Experimental Validation  
**Date:** November 2026  

---

## 1. Methodology & Theoretical Motivation

A composite intrusion detection system integrates multiple informational signals:
1. Identity anti-affinity and session tracking
2. Tenant and resource ownership boundaries
3. Field-level data sensitivity and schema classification
4. Temporal sliding-window velocity analysis
5. HTTP status codes and authorization outcomes
6. Multi-stage attack progression state machines
7. Uncertainty quantification

A core challenge in security research is determining whether all claimed signals are truly necessary or whether performance is driven by a small subset of features. A **controlled ablation study** isolates individual architectural components one at a time, evaluating their direct marginal contribution against identical telemetry.

---

## 2. Ablation Configurations Matrix

We evaluate eight distinct operational configurations:

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                              CONTROLLED ABLATION MATRIX                                               |
+--------------------------+-----------+--------+---------+-------+-----------+-----------------------------------------+
| Configuration Dimension  | Precision | Recall | F1-Score| FPR   | Delta F1  | Signal Criticality & Impact             |
+--------------------------+-----------+--------+---------+-------+-----------+-----------------------------------------+
| FULL_CONTEXTUAL (Baseline| 76.92%    | 100.00%| 0.8696  | 23.08%| 0.0000    | Complete Aegis engine                   |
| NO_OWNERSHIP             | 76.92%    | 71.43% | 0.7407  | 23.08%| -0.1289   | Rank 1: Disables resource ownership     |
| NO_SENSITIVITY           | 69.70%    | 92.00% | 0.7947  | 32.00%| -0.0749   | Rank 2: Disables schema/field labels    |
| NO_TEMPORAL              | 84.51%    | 85.71% | 0.8511  | 12.50%| -0.0185   | Rank 3: Disables sliding-window deques  |
| NO_AUTH_OUTCOME          | 81.40%    | 100.00%| 0.8974  | 18.00%| +0.0278   | Ignores HTTP 403 vs 200 distinction     |
| NO_IDENTITY_AFFINITY     | 76.92%    | 100.00%| 0.8696  | 23.08%| 0.0000    | Disables session token anti-affinity    |
| NO_STAGE_CORRELATION     | 76.92%    | 100.00%| 0.8696  | 23.08%| 0.0000    | Disables campaign state machine link    |
| NO_UNCERTAINTY_HANDLING  | 76.92%    | 100.00%| 0.8696  | 23.08%| 0.0000    | Disables explicit uncertainty tagging   |
+--------------------------+-----------+--------+---------+-------+-----------+-----------------------------------------+
```

---

## 3. Signal Criticality Ranking & Deep-Dive Analysis

### Rank 1: Resource Ownership Context (`NO_OWNERSHIP`, $\Delta F_1 = -0.1289$)
- **Impact:** Disabling caller-to-resource ownership checks caused the single largest drop in detection efficacy. Recall plummeted from **100.00% to 71.43%** ($\Delta \text{Recall} = -28.57\%$).
- **Root Cause:** In modern APIs, a BOLA/IDOR attack does not use malicious payloads; the request is a standard HTTP GET (`/api/v1/customers/1002`). Without an ownership registry mapping authenticated callers to permitted resource IDs, the detector cannot distinguish between an authorized user retrieving their own record and an adversary stealing a victim's record.
- **Architectural Conclusion:** Resource ownership context is the **single most critical invariant** for API intrusion detection. Without it, BOLA detection is structurally impossible.

### Rank 2: Field-Level Sensitivity Classification (`NO_SENSITIVITY`, $\Delta F_1 = -0.0749$)
- **Impact:** Disabling OpenAPI sensitive field classification dropped $F_1$ from **0.8696 to 0.7947**. Precision dropped to **69.70%** and False Positive Rate surged to **32.00%**.
- **Root Cause:** Without response payload classification, the system cannot detect schema drift, uncatalogued secret leakage, or excessive data exposure. Legitimate endpoints returning generic public summaries are conflated with endpoints leaking `RESTRICTED` secrets.
- **Architectural Conclusion:** Schema classification is essential for preventing excessive data exposure and maintaining SOC alert precision.

### Rank 3: Temporal Sliding-Window Velocity (`NO_TEMPORAL`, $\Delta F_1 = -0.0185$)
- **Impact:** Disabling sliding deques dropped recall to **85.71%**, as all 10 low-and-slow creeping extraction attacks slipped past undetected.
- **Root Cause:** Adversaries intentionally pace requests below rapid rate-limiting thresholds (e.g., 1 request every 80 seconds). A stateless engine evaluating events individually sees each request as an isolated read. Aegis's 600-second sliding deque retains historical request velocity across an extended window without memory exhaustion.
- **Architectural Conclusion:** Extended temporal horizons are mandatory for countering rate-limit evasive automation.

### Authorization Outcome Behavior (`NO_AUTH_OUTCOME`, $\Delta F_1 = +0.0278$)
- **Impact:** When authorization outcome context is removed (treating HTTP 403 Forbidden identically to HTTP 200 OK), apparent $F_1$ rises slightly to **0.8974**.
- **Explanation:** In this mode, denied boundary probes (HTTP 403) are counted as confirmed data compromises. While this artificially inflates scenario-level attack flags (increasing apparent precision), it severely distorts operational reality: **a blocked attack is not a data leak.** In a production SOC, distinguishing between thwarted probes and successful exfiltration is critical for incident prioritization.

### Secondary Signals (`NO_IDENTITY_AFFINITY`, `NO_STAGE_CORRELATION`, `NO_UNCERTAINTY`)
- **Impact:** At the binary scenario-level metric, $F_1$ remained unchanged at 0.8696.
- **Explanation:** These signals operate primarily at the campaign and operational triage levels. Disabling stage correlation does not prevent an alert from firing on the scenario, but it strips the SOC analyst of the multi-stage narrative (Reconnaissance $\rightarrow$ Probing $\rightarrow$ Harvesting). Similarly, disabling uncertainty handling forces the engine to make arbitrary guesses on the 50 Ambiguous / Incomplete scenarios rather than routing them to Tier-2 triage.

---

## 4. Key Architectural Takeaways

1. **Hierarchy of Security Signals:**
   $$\text{Resource Ownership} \gg \text{Data Sensitivity} > \text{Temporal Dynamics} > \text{Authorization Outcome}$$
2. **Minimal Viable Architecture:** A viable API security platform must implement at least the top 3 signals. Omitting resource ownership eliminates over a quarter of true attack detections, while omitting temporal deques leaves the API defenseless against creeping crawlers.
