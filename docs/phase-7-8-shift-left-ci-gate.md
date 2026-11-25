# Phase 7.8 — "Shift-Left" API Security CI/CD Gate CLI & GitHub Action

**Milestone:** Phase 7.8 Complete  
**Date:** 2026-11-25  
**Version:** 1.0.0  
**Status:** `VERIFIED & PRODUCTION READY`

---

## 1. Executive Summary & Objective

In modern FinTech cloud architectures, API security vulnerabilities and contract regressions introduced during development often remain undetected until deployment to staging or production. Phase 7.8 establishes a comprehensive **Shift-Left API Security CI/CD Gate** that integrates directly into developer inner-loop workflows and pull request CI/CD pipelines.

The gate evaluates OpenAPI 3.0/3.1 specifications before any backend code reaches staging environments, automatically detecting:
1. **Unauthenticated Mutating Endpoints:** Routes accepting `POST`, `PUT`, `DELETE`, or `PATCH` operations without explicit authentication/authorization requirements (`security` declarations).
2. **Sensitive Data Exposure:** Response schemas exposing unmasked or unclassified sensitive fields (e.g. `tax_id`, `ssn`, `social_security`, `credit_card`, `secret_key`, `api_key`, `auth_token`).
3. **Missing Ownership Semantics (BOLA Hazard):** Object identifiers in path parameters lacking explicit subject/tenant ownership verification semantics (OWASP API1:2023).
4. **Insecure Identifier Formats:** Sequential integer identifiers in path parameters vulnerable to brute-force enumeration attacks.
5. **Contract Breaking Regressions:** Removal of existing published endpoints or introduction of mandatory (required) parameters on existing endpoints without backward compatibility or versioning.
6. **Live Telemetry Discrepancies:** Dynamic reconciliation with running ShieldOps Gateways to identify undocumented shadow endpoints observed on wire traffic.

---

## 2. Architecture & Components

```
                +-------------------------------------------------------------+
                |                    Developer / CI Pipeline                  |
                |                                                             |
                |   git push / Pull Request (specs/**, services/**)           |
                +------------------------------+------------------------------+
                                               |
                                               v
                +-------------------------------------------------------------+
                |         Aegis ShieldOps API Security CI Gate (CLI)          |
                |                (simulation.ci_gate)                         |
                +------------------------------+------------------------------+
                                               |
                     +-------------------------+-------------------------+
                     |                                                   |
                     v                                                   v
        +-------------------------+                         +-------------------------+
        |       SpecParser        |                         |     SpecReconciler      |
        | - OpenAPI 3.0/3.1 YAML  |                         | - Contract Diffing      |
        | - Static Rule Engine    |                         | - Breaking Change Check |
        | - Schema Inspection     |                         | - Wire Telemetry Probe  |
        +------------+------------+                         +------------+------------+
                     |                                                   |
                     +-------------------------+-------------------------+
                                               |
                                               v
                                +------------------------------+
                                |         GateReporter         |
                                | - Terminal ANSI Color Output |
                                | - GitHub PR Markdown Tables  |
                                | - Machine-Readable JSON      |
                                +--------------+---------------+
                                               |
                                               v
                                +------------------------------+
                                |  CI Exit Code Enforcement    |
                                |   Exit 0: Clean / Passed     |
                                |   Exit 1: Breaking / Flaw    |
                                |   Exit 2: Parsing / Error    |
                                +------------------------------+
```

### 2.1 Component Overview

| Component | Path | Responsibility |
| :--- | :--- | :--- |
| **CLI Entry Point** | `simulation/src/simulation/ci_gate/cli.py` | Typer-based CLI implementing `scan`, `diff`, `version` commands and strict exit code mapping. |
| **Standalone Runner** | `tools/aegis-ci-gate/aegis_ci_gate.py` | Standalone Python executable runner usable across developer workstations and CI runners. |
| **Data Models** | `simulation/src/simulation/ci_gate/models.py` | Pydantic v2 schemas for `GateFinding`, `GateSummary`, `GateReport`, `OperationDiff`, `GateVerdict`, and `Severity`. |
| **Spec Parser & Rules** | `simulation/src/simulation/ci_gate/parser.py` | Parses YAML/JSON OpenAPI contracts; evaluates authentication, sensitive data exposure, and BOLA rules. |
| **Reconciler & Diff** | `simulation/src/simulation/ci_gate/reconciler.py` | Computes structural contract diffs; queries live Gateway reconciliation API for shadow wire routes. |
| **Multi-Format Reporter** | `simulation/src/simulation/ci_gate/reporter.py` | Formats evaluation results into Terminal ANSI, GitHub PR Markdown with callout alerts, or JSON. |
| **GitHub Composite Action** | `.github/actions/aegis-ci-gate/action.yml` | Reusable GitHub Action composite step for CI pipelines. |
| **GitHub CI Workflow** | `.github/workflows/aegis-api-security-gate.yml` | Dedicated automated PR gate auditing all microservice specs. |

---

## 3. Shift-Left Security Rules Engine

### 3.1 Rule Taxonomy

| Rule ID | Severity | Category | Description | Default Action |
| :--- | :---: | :--- | :--- | :--- |
| `RULE-GATE-AUTH-*` | **CRITICAL** | Authentication | Mutating endpoint (`POST`, `PUT`, `DELETE`, `PATCH`) declared without security schemes. | **BLOCKS CI** (`breaking=True`) |
| `RULE-GATE-AUTH-*` | **MEDIUM** | Authentication | Read endpoint (`GET`) publicly accessible without security schemes or public tags. | Warning logged |
| `RULE-GATE-LEAK-*` | **CRITICAL** | Data Exposure | Response schema exposes unmasked sensitive fields (`ssn`, `tax_id`, `credit_card`, `secret_key`). | **BLOCKS CI** (`breaking=True`) |
| `RULE-GATE-BOLA-*` | **HIGH** | Authorization | Direct object reference (`{id}`) lacks explicit subject or tenant ownership semantics. | Advisory warning |
| `RULE-GATE-FMT-*` | **LOW** | Parameter Safety | Path parameter uses sequential integer identifier vulnerable to enumeration. | Advisory warning |
| `RULE-GATE-BREAK-*`| **HIGH** | Contract Regress | Previously published endpoint removed from candidate specification. | **BLOCKS CI** (`breaking=True`) |
| `RULE-GATE-PARAM-*`| **HIGH** | Contract Regress | New required parameter added or optional parameter changed to required on existing endpoint. | **BLOCKS CI** (`breaking=True`) |
| `RULE-GATE-SHADOW-*`| **HIGH**| Wire Telemetry | Active wire traffic observed on Gateway for endpoint not declared in contract. | Advisory warning |

### 3.2 Scoring Methodology

$$\text{Posture Score} = \max\left(0, 100 - \left(25 \times N_{\text{crit}} + 15 \times N_{\text{high}} + 5 \times N_{\text{med}} + 1 \times N_{\text{low}}\right)\right)$$

- **Pass Verdict (`PASSED`):** Zero breaking changes AND posture score $\ge 75.0\%$. (Exit code 0)
- **Warning Verdict (`WARNING`):** Zero breaking changes, posture score $\ge 75.0\%$, but medium/high advisory findings present. (Exit code 0)
- **Fail Verdict (`FAILED`):** Any breaking change ($N_{\text{breaking}} > 0$) OR posture score $< 75.0\%$. (Exit code 1)

---

## 4. CLI Usage & Commands

### 4.1 `scan` Command

Evaluates an OpenAPI contract against shift-left security rules, contract regression diffs, and live Gateway wire telemetry.

```bash
# Basic offline scan with terminal output
python tools/aegis-ci-gate/aegis_ci_gate.py scan gateway/src/main/resources/specs/customer-service.yaml

# Markdown report written to file with base spec diffing
python tools/aegis-ci-gate/aegis_ci_gate.py scan candidate-spec.yaml \
  --base-spec production-spec.yaml \
  --format markdown \
  --output-file gate-report.md

# Scan connected to running ShieldOps Gateway
python tools/aegis-ci-gate/aegis_ci_gate.py scan gateway/src/main/resources/specs/account-service.yaml \
  --gateway-url http://localhost:8000 \
  --token $SHIELDOPS_API_TOKEN \
  --threshold 80.0
```

### 4.2 `diff` Command

Computes structural differences and breaking changes between two specification revisions.

```bash
python tools/aegis-ci-gate/aegis_ci_gate.py diff base-spec.yaml target-spec.yaml --format markdown
```

### 4.3 `version` Command

Prints the CI Gate version.

```bash
python tools/aegis-ci-gate/aegis_ci_gate.py version
```

---

## 5. GitHub Action & CI Workflow Integration

### 5.1 Reusable Composite Action (`.github/actions/aegis-ci-gate/action.yml`)

The composite action automates environment setup, dependency resolution, execution, and appends the markdown report to GitHub Step Summaries (`$GITHUB_STEP_SUMMARY`).

```yaml
- name: Audit Customer Service OpenAPI Spec
  uses: ./.github/actions/aegis-ci-gate
  with:
    spec-file: 'gateway/src/main/resources/specs/customer-service.yaml'
    threshold: '75.0'
    fail-on-breaking: 'true'
    output-format: 'markdown'
    output-file: 'customer-service-report.md'
```

### 5.2 CI Workflow (`.github/workflows/aegis-api-security-gate.yml`)

Triggered on pull requests modifying OpenAPI specifications or gate tools, running automated audits across all microservices (`customer-service`, `account-service`, `transaction-service`).

---

## 6. Verification & Automated Test Results

The Shift-Left CI Gate is verified across the complete Aegis test matrix:

| Test Layer | Test Count | Failures | Status |
| :--- | :---: | :---: | :--- |
| **CI Gate Unit & Integration Tests** (`test_ci_gate.py`) | **19** | **0** | **100% PASSED** |
| **Total Python Simulation Suite** (`simulation/tests`) | **164** | **0** | **100% PASSED** |
| **Frontend Karma Suite** (`frontend/src/**/*.spec.ts`) | **226** | **0** | **100% PASSED** |
| **Frontend Production Build** (`ng build`) | — | **0** | **100% SUCCESS** |
| **Backend Platform Tests** (`mvn test`) | **471** | **0** | **100% BUILD SUCCESS** |
| **Grand Total Automated Tests** | **861** | **0** | **100% VERIFIED** |

---

## 7. Next Milestones

With Phase 7.8 complete:
- **Phase 7.9 (Option C):** Advanced Anomaly Detection ML Pipeline & Production Readiness (Online clustering of API access sequences, Isolation Forest outlier scoring on response latencies and payload sizes, automated canary evaluation).
