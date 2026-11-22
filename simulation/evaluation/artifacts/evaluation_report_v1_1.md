# ShieldOps Research Evaluation Benchmark Report (v1.1.0)
**Dataset:** `DS-AEGIS-RESEARCH-V1.1` | **Manifest Hash:** `83e67d66853de0ca17ad4e94617470df5ea50f62409d7fc857577090138d9f78` | **Total Scenarios:** `200`

## 1. Population Accounting & Evaluation Coverage
- **Total Dataset Scenarios:** 200
- **Primary Binary Evaluation Population:** 150 (80 Benign, 70 Malicious)
- **Secondary Ambiguous / Incomplete Population:** 50 (30 Ambiguous, 20 Incomplete)
- **Binary Evaluation Coverage:** 75.0%
- **Accounting Reconciled:** True

## 2. Primary Binary Detection Performance (n=150)
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | True FPR | FDR | Accuracy |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules (Baseline)** | 30 | 10 | 70 | 40 | 75.00% | 42.86% | 0.5455 | 12.50% | 25.00% | 66.67% |
| **Contextual Detection (Aegis)** | 70 | 0 | 80 | 0 | 100.00% | 100.00% | 1.0000 | 0.00% | 0.00% | 100.00% |

## 3. Paired Comparative Statistical Significance (n=150)
- **Exact Two-Sided McNemar Test:**
  - Discordant pairs: Isolated correct / Contextual incorrect (b) = 0, Isolated incorrect / Contextual correct (c) = 50
  - Exact p-value: `0.000000` (STATISTICALLY SIGNIFICANT at alpha=0.05)
  - Odds Ratio (c/b): `999.0`
- **Paired Scenario-Level Bootstrap (B=2000):**
  - Δ F1: `+0.4545` (95% CI: [+0.3496, +0.5686])
  - Δ FPR: `-0.1250` (95% CI: [-0.2025, -0.0595])
  - Δ Precision: `+0.2500` (95% CI: [+0.1250, +0.3913])
  - Δ Recall: `+0.5714` (95% CI: [+0.4557, +0.6818])
  - Δ Accuracy: `+0.3333`

## 4. Secondary Population Disposition & Uncertainty Handling (n=50)
| Disposition | Isolated Rules | Contextual Correlation |
|:---|:---:|:---:|
| **Abstained / Flagged Uncertain (Safe Triage)** | 0 (0.0%) | 28 (56.0%) |
| **Over-Escalated as Attack (False Alarm)** | 11 (22.0%) | 11 (22.0%) |
| **Silently Passed as Benign (Under-Investigation)** | 39 (78.0%) | 11 (22.0%) |

## 5. Controlled Ablation Study (Primary Binary Population n=150)
| Ablation Configuration | Precision | Recall | F1 Score | True FPR | Delta vs Full |
|:---|:---:|:---:|:---:|:---:|:---:|
| **FULL_CONTEXTUAL** | 100.00% | 100.00% | 1.0000 | 0.00% | BASELINE |
| **NO_IDENTITY** | 100.00% | 100.00% | 1.0000 | 0.00% | BASELINE |
| **NO_TENANT** | 100.00% | 100.00% | 1.0000 | 0.00% | BASELINE |
| **NO_OWNERSHIP** | 100.00% | 85.71% | 0.9231 | 0.00% | -0.0769 |
| **NO_SENSITIVITY** | 100.00% | 85.71% | 0.9231 | 0.00% | -0.0769 |
| **NO_AUTH_OUTCOME** | 100.00% | 100.00% | 1.0000 | 0.00% | BASELINE |
| **NO_TEMPORAL** | 100.00% | 85.71% | 0.9231 | 0.00% | -0.0769 |
| **NO_CAMPAIGN** | 100.00% | 100.00% | 1.0000 | 0.00% | BASELINE |

## 6. Dynamic Robustness & Adversarial Edge-Case Validation
| Test Case | Category | Expected Behavior | Observed Behavior | Status |
|:---|:---|:---|:---|:---:|
| **Shared-IP NAT Disambiguation** | Identity & Network | Distinct customers on shared NAT (203.0.113.50) partitioned without false alarm | Detected=False, Rules=[] | `PASS` |
| **Cross-Owner Account Detail Probe** | Resource Ownership | Mismatched resource_owner_id correctly triggers RULE-BOLA-01 | Detected=True, Rules=['RULE-BOLA-01'] | `PASS` |
| **Restricted Secret Exposure in Response** | Sensitivity Classification | Leaking auth_token_hash triggers RULE-EXCESSIVE-EXPOSURE-01 | Detected=True, Rules=['RULE-EXCESSIVE-EXPOSURE-01'] | `PASS` |
| **Sliding-Window Temporal Eviction (120s)** | Temporal Behavior | Access beyond 120s window avoids rapid burst trigger | Detected=True, Rules=['RULE-BOLA-CONFIRMED-01'] | `PASS` |
| **Automated Pagination Table Scraping** | API Behavior | Rapid access across >= 3 distinct pages triggers RULE-ADV-EXTRACT-01 | Detected=True, Rules=['RULE-ADV-EXTRACT-01'] | `PASS` |
| **Missing Resource Ownership Uncertainty** | Uncertainty & Incomplete Evidence | Missing customer ownership on customer route flagged as UNCERTAIN | is_uncertain=True, explanation=Ambiguous/Incomplete evidence requiring analyst review | `PASS` |
| **Multi-Stage Kill-Chain Progression** | Campaign Correlation | Recon (404) + Probing (403) + Extraction (200) escalated to DATA_EXFILTRATION_CAMPAIGN | campaign_identified=True, Rules=['DATA_EXFILTRATION_CAMPAIGN', 'RULE-BOLA-01', 'RULE-BOLA-CONFIRMED-01', 'RULE-PROBE-01'] | `PASS` |
