# Phase 7.3.6 — Reproducibility & Replication Guide

**Research Title:** Intrusion Detection and Adaptive Security Response Through API Activity Analysis  
**Project:** ShieldOps (Aegis Security Operations Platform)  
**Milestone:** Phase 7.3.6 — Research Evaluation & Experimental Validation  
**Repository:** `https://github.com/NIKHILGONUGUNTA-STACK/shieldops`  
**Date:** November 2026  

---

## 1. Overview & Verification Philosophy

Scientific integrity requires that every empirical finding, metric, statistical interval, and ablation outcome reported in this study can be independently replicated from scratch on a clean environment.

This guide provides step-by-step instructions for:
1. Generating the exact 200-scenario evaluation dataset with SHA-256 verification.
2. Executing the Python dual-mode evaluation framework and computing non-parametric Bootstrap confidence intervals.
3. Running the Spring Boot Java 25 backend integration tests.
4. Verifying persistent database storage in PostgreSQL under Flyway V11.
5. Querying the live REST API endpoints and inspecting the Angular SOC Operations Console.

---

## 2. Environment Prerequisites

- **Operating System:** Linux (Ubuntu 22.04+), macOS (13+), or Windows 11 with PowerShell.
- **Java:** OpenJDK 25 (Temurin or Microsoft build).
- **Python:** Python 3.14 (or Python 3.11+) with `pip` and virtual environment.
- **Node.js:** Node.js v20.x or v22.x with npm.
- **Docker:** Docker Engine 24+ and Docker Compose v2.

---

## 3. Step-by-Step Reproduction Instructions

### Step 3.1: Python Simulation & Evaluation Framework Setup
From the repository root:
```bash
# Navigate to simulation directory
cd simulation

# Create and activate virtual environment
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows PowerShell:
.venv\Scripts\Activate.ps1

# Install simulation package in editable mode with evaluation dependencies
pip install -e .
```

### Step 3.2: Dataset Generation & Cryptographic Verification
To regenerate or inspect the canonical evaluation dataset (`DS-AEGIS-RESEARCH-V1`):
```bash
# List available research datasets
python -m simulation.cli evaluate datasets list

# Regenerate the 200-scenario dataset with deterministic PRNG seed=42
python -m simulation.cli evaluate generate --dataset-id DS-AEGIS-RESEARCH-V1 --scenarios 200 --seed 42

# Verify manifest SHA-256 cryptographic integrity
python -m simulation.cli evaluate validate --dataset-id DS-AEGIS-RESEARCH-V1
```
*Expected Output:*
```
Dataset ID: DS-AEGIS-RESEARCH-V1
Total Scenarios: 200 (80 Benign, 70 Malicious, 30 Ambiguous, 20 Incomplete)
Total Events: 640
Manifest SHA-256: b8ba6bd4bb22d9ebd0a38a9cd58de601fcbc227f18a55f06ce47f4b86180df18
Verification Status: VALID (Zero label leakage verified)
```

### Step 3.3: Execute Dual-Mode Evaluation Benchmark
Run the dual-mode comparative evaluation comparing Isolated Rules vs Contextual Correlation (Aegis):
```bash
# Run full evaluation across all 4 evaluation units
python -m simulation.cli evaluate run --dataset-id DS-AEGIS-RESEARCH-V1

# Print side-by-side comparative table with Bootstrap 95% CIs
python -m simulation.cli evaluate compare --dataset-id DS-AEGIS-RESEARCH-V1
```
*Expected Output:*
```
Scenario Precision (Contextual): 76.92% (Isolated: 59.70%, Delta: +17.22%)
Scenario Recall (Contextual):    100.00% (Isolated: 57.14%, Delta: +42.86%)
Scenario F1 (Contextual):        0.8696 (Isolated: 0.5839, Delta: +0.2857)
Bootstrap 95% CI (Contextual):   [0.8132, 0.9218]
Bootstrap 95% CI (Isolated):     [0.4852, 0.6781]
Statistical Separation:          Non-overlapping intervals (p < 0.001)
```

### Step 3.4: Execute Controlled Ablation & Robustness Studies
```bash
# Run 8-configuration controlled ablation study
python -m simulation.cli evaluate ablation --dataset-id DS-AEGIS-RESEARCH-V1

# Run deterministic boundary robustness tests
python -m simulation.cli evaluate robustness

# Generate comprehensive JSON and Markdown research reports
python -m simulation.cli evaluate report --dataset-id DS-AEGIS-RESEARCH-V1 --output-dir evaluation/artifacts
```

### Step 3.5: Execute Python Evaluation Test Suite
Verify that all unit and statistical tests pass cleanly:
```bash
pytest tests/test_research_evaluation_suite.py -v
```
*Expected Result:* `7 passed in 5.3s`.

---

## 4. Backend Spring Boot & PostgreSQL Verification

### Step 4.1: Flyway V11 Database Migration Verification
Ensure Docker containers are running (`docker compose up -d`). Verify that Flyway migration `V11__research_evaluation_framework.sql` has applied:
```bash
docker exec -it aegis-postgres-1 psql -U aegis_owner -d aegis_db -c "\dt security_data.evaluation_*"
```
*Expected Tables:*
- `security_data.evaluation_datasets`
- `security_data.evaluation_experiments`
- `security_data.evaluation_results`
- `security_data.evaluation_ablations`
- `security_data.evaluation_robustness_findings`

### Step 4.2: Run Gateway Integration Tests
```bash
cd gateway
./mvnw test -Dtest=ResearchEvaluationControllerTest
```
*Expected Result:* `Tests run: 5, Failures: 0, Errors: 0, Skipped: 0` (BUILD SUCCESS).

### Step 4.3: Query Live Evaluation REST APIs
Obtain Keycloak analyst/admin bearer token and test the endpoints:
```bash
# 1. Fetch live evaluation benchmark
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/security/evaluation/benchmark | jq .

# 2. List durable experiments
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/security/evaluation/experiments | jq .
```

---

## 5. Angular SOC Operations Console Verification

To view the live research evaluation dashboard in the browser:
```bash
cd frontend
npm start
```
1. Open `http://localhost:4200` in the browser.
2. Authenticate as a SOC analyst (`admin` / `Password123!`).
3. Navigate to **Data Leakage & BOLA Correlation** (`/data-leakage`).
4. Select the **Research Evaluation & Adversarial Robustness** sub-tab.
5. Verify the live rendering of all 7 sections:
   - Overview & SHA-256 Manifest Hash
   - Comparative Metrics across Scenario, Event, and Campaign units
   - Operational Latency & Throughput KPIs
   - Controlled Ablation Table with Signal Criticality Rankings
   - Robustness Findings Matrix (7 PASS badges)
   - Bootstrap 95% Confidence Intervals
   - Reproducibility Guidance and Experiment Provenance
