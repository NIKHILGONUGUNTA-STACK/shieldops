# Phase 7.2.4.6: Adaptive Security Response and Policy Decision Engine

**Repository:** `NIKHILGONUGUNTA-STACK/shieldops`  
**Branch:** `main`  
**Baseline commit:** `32222df`  
**Status:** `VERIFIED & PRODUCTION READY`

---

## 1. Executive Summary

Phase 7.2.4.6 implements a context-aware, explainable, advisory-only **Adaptive Security Response and Policy Decision Engine** within the ShieldOps platform.

The engine translates evidence-backed security incidents and multi-stage exfiltration campaigns into structured, reproducible security policy recommendations. Operating under a strict non-intrusive safety invariant, the engine provides SOC analysts with structured decision rationales, frozen telemetry snapshots, and actionable guidance without ever executing autonomous traffic blocking, rate throttling, credential revocations, or ledger mutations.

---

## 2. Core Architectural Principles

```
                  ┌──────────────────────────────────────────────┐
                  │             DETECTION PIPELINE               │
                  │ (ThreatDetectionEngine / CampaignCorrelator) │
                  └──────────────────────┬───────────────────────┘
                                         │ (Emits Incidents / Campaigns)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │         ADAPTIVE POLICY ENGINE               │
                  │   - Evidence Completeness Evaluation Gate    │
                  │   - Policy Registry Matching                 │
                  │   - Risk Scoring & Threshold Verification   │
                  │   - Frozen Telemetry & Evidence Snapshotting │
                  └──────────────────────┬───────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   ▼                                           ▼
┌──────────────────────────────────────┐     ┌───────────────────────────────────┐
│     PERSISTENCE & AUDIT LAYER        │     │         SOC DASHBOARD UI          │
│ - security_data.policy_decisions     │     │ - Advisory Decision Queue         │
│ - security_data.security_policies    │     │ - Policy Governance & Tuning      │
│ - security_data.policy_audit_history │     │ - Analyst Approval / Rejection    │
│ - security_data.policy_decision_acts │     │ - Frozen Evidence Inspector       │
└──────────────────────────────────────┘     └───────────────────────────────────┘
```

1. **Strict Non-Intrusive Advisory Invariant:**  
   The platform operates in `ADVISORY ONLY` mode. Security recommendations (`ESCALATE_INCIDENT`, `REVIEW_AUTHORIZATION`, `REVIEW_DATA_EXPOSURE`, `INVESTIGATE_ACTIVITY`, `PRIORITIZE_CAMPAIGN`, `MONITOR_ACTIVITY`, `REQUEST_ADDITIONAL_EVIDENCE`) empower human SOC analysts with decision context. Zero autonomous blocks, zero rate limits, zero credential revocations, and zero database mutations occur.
2. **Strict Separation of Concerns:**  
   Policy decision logic is decoupled from detection rule evaluation (`RuleBolaConfirmed01`, `RuleBulkExtract01`, etc.) and from incident status lifecycle management (`IncidentService`).
3. **Deterministic Reproducibility & Frozen Snapshots:**  
   Every policy recommendation captures a frozen JSON snapshot of the contributing incident, detection evidence, campaign metrics, and policy version at evaluation time.
4. **Evidence Completeness Safeguard:**  
   Degraded, incomplete, or ambiguous telemetry automatically routes to `POL-AMBIGUOUS-EVIDENCE-01`, suppressing severe response actions and recommending `REQUEST_ADDITIONAL_EVIDENCE`.

---

## 3. Policy Decision Model & Governance

### 3.1 Structured Decision Entity (`AdaptivePolicyDecision`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `UUID` | Unique primary key of the policy recommendation. |
| `incidentId` | `UUID?` | Foreign key referencing associated security incident (nullable). |
| `campaignId` | `UUID?` | Foreign key referencing associated exfiltration campaign (nullable). |
| `policyId` | `String` | Unique policy identifier (e.g. `POL-BOLA-CONFIRMED-01`). |
| `policyVersion` | `String` | Semantic version of the policy at decision time (e.g. `1.0.0`). |
| `category` | `PolicyCategory` | Threat category (`RECONNAISSANCE`, `AUTHORIZATION`, `DATA_EXPOSURE`, `BULK_EXTRACTION`, `CAMPAIGN`, `EVIDENCE_INTEGRITY`). |
| `riskLevel` | `String` | Advisory risk severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `recommendedAction` | `PolicyAction` | Structured recommendation for SOC analysts. |
| `enforcementLevel` | `String` | Always `ADVISORY` in Phase 7.2.4.6. |
| `rationale` | `String` | Human-readable explanation of why this policy was selected. |
| `supportingEvidence` | `List<String>` | URNs and IDs of contributing events, evidence records, and incident references. |
| `identityContext` | `String` | Authenticated subject, customer ID, or client IP. |
| `tenantId` | `String` | Multi-tenant partition boundary. |
| `evidenceCompleteness`| `CampaignEvidenceCompleteness` | `COMPLETE`, `INCOMPLETE`, or `DEGRADED`. |
| `evidenceSnapshot` | `String (JSON)` | Immutable snapshot of incident, risk score, and telemetry state. |
| `status` | `PolicyStatus` | `RECOMMENDED`, `UNDER_REVIEW`, `APPROVED`, `REJECTED`, `SUPERSEDED`. |
| `analystUser` | `String?` | Username of analyst reviewing the decision. |
| `analystAction` | `String?` | `APPROVED` or `REJECTED`. |
| `analystRationale` | `String?` | Mandatory rationale provided on rejection or notes on approval. |
| `analystActionAt` | `Instant?` | Timestamp when analyst recorded decision. |

### 3.2 Security Policy Registry (`security_data.security_policies`)

| Policy ID | Policy Name | Default Action | Risk Threshold | Category | Trigger Condition Description |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `POL-RECON-01` | Repeated Reconnaissance Probing Policy | `MONITOR_ACTIVITY` | 20.0 | `RECONNAISSANCE` | Repeated 404 scans on actuator, Swagger, or debug endpoints without bypass. |
| `POL-BOLA-PROBE-01` | Authorization Probing Verification Policy | `REVIEW_AUTHORIZATION` | 45.0 | `AUTHORIZATION` | Authenticated identity queries peer resources resulting in 403 Forbidden. |
| `POL-BOLA-CONFIRMED-01`| Confirmed Unauthorized Access Escalation Policy | `ESCALATE_INCIDENT` | 85.0 | `AUTHORIZATION` | Authenticated identity successfully accesses cross-owner customer/account entity (200 OK). |
| `POL-DATA-EXPOSURE-01` | Excessive Data Exposure & Schema Drift Policy | `REVIEW_DATA_EXPOSURE` | 70.0 | `DATA_EXPOSURE` | Backend response payloads leak undeclared CONFIDENTIAL or RESTRICTED fields. |
| `POL-BULK-EXTRACT-01` | Rapid Bulk Extraction Investigation Policy | `INVESTIGATE_ACTIVITY` | 75.0 | `BULK_EXTRACTION` | >= 3 distinct sensitive resources or multiple pagination pages harvested rapidly. |
| `POL-LOW-SLOW-01` | Low-and-Slow Extraction Tracking Policy | `INVESTIGATE_ACTIVITY` | 65.0 | `BULK_EXTRACTION` | Sub-threshold retrieval across extended sliding windows (>= 5 resources in 600s). |
| `POL-MULTI-DOMAIN-01` | Multi-Domain Cross-Entity Extraction Policy | `INVESTIGATE_ACTIVITY` | 80.0 | `BULK_EXTRACTION` | Extraction spans >= 2 independent entity domains (Customer, Account, Transfer). |
| `POL-CAMPAIGN-01` | Multi-Stage Campaign Prioritization Policy | `PRIORITIZE_CAMPAIGN` | 85.0 | `CAMPAIGN` | Correlated progression through >= 2 stages culminating in bulk/cross-domain access. |
| `POL-AMBIGUOUS-EVIDENCE-01`| Incomplete or Ambiguous Evidence Policy | `REQUEST_ADDITIONAL_EVIDENCE`| 30.0 | `EVIDENCE_INTEGRITY` | Missing ownership context, unclassified fields, or incomplete telemetry sequence. |

---

## 4. Analyst Governance & SOC Dashboard Integration

The Angular SOC Dashboard (`/policy-decisions`) provides end-to-end governance:
- **Decision Queue Tab:**
  - Status chips (`RECOMMENDED`, `UNDER_REVIEW`, `APPROVED`, `REJECTED`, `SUPERSEDED`)
  - Risk badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
  - Evidence completeness indicators (`COMPLETE`, `INCOMPLETE`, `DEGRADED`)
  - Filtering by status, threat category, and full-text keyword search
- **Interactive Inspection Drawer:**
  - Detailed metadata, identity context, and policy rationale
  - One-click navigation to linked Security Incident (`/incidents/{id}`) or Attack Campaign (`/campaigns`)
  - Contributing evidence URN list
  - Immutable frozen telemetry JSON viewer
  - Decision audit log (`security_data.policy_decision_actions`)
  - **Approval Control:** Approve recommendation with analyst notes
  - **Rejection Control:** Rejection button is disabled until mandatory operational rationale is provided
- **Policy Registry Tab:**
  - Inspection of all active security policies
  - Version tracking (`1.0.0` -> `1.1.0`)
  - Threshold tuning interface with mandatory change reason recording into `security_data.policy_audit_history`

---

## 5. Verification & Research Evaluation

### 5.1 Test Execution Matrix

| Test Suite | Scope | Tests Run | Pass Rate |
| :--- | :--- | :---: | :---: |
| **Backend Policy Engine Unit Tests** | `AdaptivePolicyEngineTest` | 5 | 100% |
| **Backend Policy Controller Tests** | `PolicyControllerTest` | 6 | 100% |
| **Backend Platform Tests** | Maven Surefire (`gateway`, `services`) | 318 | 100% |
| **Frontend SOC Dashboard Tests** | Karma / Jasmine (`policy-decisions.component.spec.ts`) | 194 | 100% |
| **Frontend Production Build** | Angular CLI AOT compilation (`ng build`) | 1 | 100% |
| **Python Simulation Scenarios** | Pytest (`simulation/tests/test_policy_engine.py`) | 14 | 100% |
| **Full Simulation Testbed** | Pytest (`simulation/tests/`) | 109 | 100% |
| **Cumulative Automated Tests** | Across all tiers | **638** | **100%** |

### 5.2 14 Required Evaluation Scenarios

| # | Evaluation Scenario | Tested Policy | Recommended Action | Risk Level | Evidence Completeness | Outcome |
| :-: | :--- | :--- | :--- | :---: | :---: | :---: |
| 1 | Repeated Reconnaissance | `POL-RECON-01` | `MONITOR_ACTIVITY` | `LOW` | `COMPLETE` | PASS |
| 2 | Authorization Probing (403 denials) | `POL-BOLA-PROBE-01` | `REVIEW_AUTHORIZATION` | `MEDIUM` | `COMPLETE` | PASS |
| 3 | Confirmed Unauthorized Access | `POL-BOLA-CONFIRMED-01` | `ESCALATE_INCIDENT` | `CRITICAL` | `COMPLETE` | PASS |
| 4 | Sensitive Data Exposure | `POL-DATA-EXPOSURE-01` | `REVIEW_DATA_EXPOSURE` | `HIGH` | `COMPLETE` | PASS |
| 5 | Excessive Exposure & Schema Drift | `POL-DATA-EXPOSURE-01` | `REVIEW_DATA_EXPOSURE` | `HIGH` | `COMPLETE` | PASS |
| 6 | Rapid Bulk Extraction | `POL-BULK-EXTRACT-01` | `INVESTIGATE_ACTIVITY` | `HIGH` | `COMPLETE` | PASS |
| 7 | Low-and-Slow Extraction | `POL-LOW-SLOW-01` | `INVESTIGATE_ACTIVITY` | `MEDIUM` | `COMPLETE` | PASS |
| 8 | Multi-Domain Extraction | `POL-MULTI-DOMAIN-01` | `INVESTIGATE_ACTIVITY` | `HIGH` | `COMPLETE` | PASS |
| 9 | Multi-Stage Exfiltration Campaign | `POL-CAMPAIGN-01` | `PRIORITIZE_CAMPAIGN` | `CRITICAL` | `COMPLETE` | PASS |
| 10 | Incomplete / Ambiguous Evidence | `POL-AMBIGUOUS-EVIDENCE-01` | `REQUEST_ADDITIONAL_EVIDENCE` | `MEDIUM` | `INCOMPLETE` | PASS |
| 11 | Missing Context / Degraded Telemetry | `POL-AMBIGUOUS-EVIDENCE-01` | `REQUEST_ADDITIONAL_EVIDENCE` | `MEDIUM` | `DEGRADED` | PASS |
| 12 | Disabled Policy Handling | `POL-BOLA-CONFIRMED-01` (Disabled)| `MONITOR_ACTIVITY` | `CRITICAL` | `COMPLETE` | PASS |
| 13 | Policy Version & Audit Retention | Policy Tuning API | Version Bump (`1.0.0` -> `1.1.0`)| N/A | N/A | PASS |
| 14 | Analyst Approval & Rejection | Decision Workflow | `APPROVED` / `REJECTED` | N/A | N/A | PASS |

---

## 6. Safety Invariant Audit

- [x] Zero autonomous blocking actions generated.
- [x] Zero autonomous rate throttling or connection drops.
- [x] Zero autonomous Keycloak token invalidations or user account lockouts.
- [x] Zero financial ledger mutations or transfers altered.
- [x] All generated policy recommendations persist `enforcement_level = 'ADVISORY'`.
- [x] Mandatory operational rationale enforced for all decision rejections.
- [x] Full policy configuration change history persisted with analyst identity.
