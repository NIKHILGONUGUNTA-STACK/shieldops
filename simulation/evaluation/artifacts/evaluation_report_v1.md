# ShieldOps Research Evaluation Benchmark Report (v1.0.0)
**Dataset:** `DS-AEGIS-RESEARCH-V1` | **Hash:** `b8ba6bd4bb22d9ebd0a38a9cd58de601fcbc227f18a55f06ce47f4b86180df18` | **Scenarios:** `200`

## 1. Scenario-Level Detection Performance
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score | FPR | Median Latency |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules (Baseline)** | 40 | 27 | 70 | 30 | 59.70% | 57.14% | 0.5839 | 27.84% | 0.02 ms |
| **Contextual Detection (Aegis)** | 70 | 21 | 70 | 0 | 76.92% | 100.00% | 0.8696 | 23.08% | 0.03 ms |

## 2. Event-Level Detection Performance
| Approach | TP | FP | TN | FN | Precision | Recall | F1 Score |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Isolated Rules** | 60 | 77 | 323 | 130 | 43.80% | 31.58% | 0.3670 |
| **Contextual Detection** | 190 | 51 | 349 | 0 | 78.84% | 100.00% | 0.8817 |
