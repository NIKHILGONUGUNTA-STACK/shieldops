# Aegis FinTech Simulation Framework

The Aegis Simulation Framework is a modular Python package designed to generate realistic FinTech banking workflows and controlled security attack scenarios against the Aegis Security Gateway and threat detection engine.

## Status

**Current Milestone:** Phase 7.2.3.1 — First End-to-End Benign FinTech Customer Journey (`SCEN-BENIGN-01`)  
**Executable Scenarios:** `SCEN-BENIGN-01` (Implemented & Verified); 8 Adversarial Scenarios Planned (Phase 7.2.3.2+)

---

## 1. Architecture Overview

```
simulation/
├── pyproject.toml              # Modern pyproject.toml packaging and dependencies
├── .env.example                # Local environment configuration template
├── .gitignore                  # Git ignore rules for venv, cache, and secrets
├── config/
│   └── default.yaml            # Default local testbed YAML configuration
├── src/simulation/
│   ├── __init__.py             # Package root and version definition
│   ├── config.py               # Pydantic v2 configuration models & local isolation
│   ├── models.py               # Scenario metadata, categories, request & summary models
│   ├── cli.py                  # Typer & Rich CLI (validate, doctor, scenarios list)
│   ├── auth/
│   │   ├── __init__.py
│   │   └── keycloak.py         # Keycloak OIDC Direct Access Grants & token caching
│   ├── clients/
│   │   ├── __init__.py
│   │   └── gateway.py          # Async HTTPX client, correlation ID & safe retries
│   ├── scenarios/
│   │   ├── __init__.py
│   │   ├── base.py             # Abstract BaseScenario with lifecycle error trapping
│   │   ├── registry.py         # ScenarioRegistry with 9 planned attack categories
│   │   ├── benign_customer_flow.py # SCEN-BENIGN-01 End-to-end customer journey
│   │   └── soc_verifier.py     # Independent SOC telemetry verification
│   └── reporting/
│       ├── __init__.py
│       └── reporter.py         # Execution reporting with zero-token leak guarantees
└── tests/                      # 41 comprehensive Pytest unit tests (100% mocked)
    ├── test_config.py          # Configuration loading, validation, and safeguards
    ├── test_auth.py            # Keycloak token acquisition, caching, and refresh
    ├── test_gateway_client.py  # Correlation ID, safe retries, and synthetic IP safety
    ├── test_scenario_models.py # Scenario models, registry, and report redaction
    ├── test_cli.py             # CLI commands, doctor diagnostic, and error exits
    └── test_benign_customer_flow.py # SCEN-BENIGN-01 execution, dry-run & SOC verifier
```

---

## 2. Environment Setup & Installation

### Requirements
- Python 3.11+ (Python 3.14 supported)
- Virtual environment (`venv`)

### Installation

```powershell
# Navigate to simulation directory
cd simulation

# Create virtual environment
python -m venv .venv

# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Install in editable mode with development/test dependencies
pip install -e ".[dev]"
```

---

## 3. Configuration & Local Isolation Safeguards

The framework uses typed Pydantic v2 models loaded from `config/default.yaml` and environment variables.

### Local-Only Testbed Safeguards
To prevent accidental transmission of synthetic traffic or attack payloads to non-local networks:
- All target service hosts (`gateway.base_url`, `keycloak.base_url`, downstream URLs) **must** resolve to localhost (`localhost`, `127.0.0.1`, `::1`).
- Non-local URLs trigger a `ValueError` on startup unless `execution.allow_non_local: true` is explicitly configured.

### Environment Variable Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SIMULATION_GATEWAY_BASE_URL` | `http://localhost:8000` | Target URL for the Aegis API Gateway |
| `SIMULATION_HTTP_TIMEOUT_SECONDS` | `10.0` | Request timeout in seconds |
| `SIMULATION_MAX_RETRIES` | `2` | Max retries for safe idempotent requests |
| `SIMULATION_ALLOW_SYNTHETIC_SOURCE_IP` | `false` | Whether synthetic `X-Forwarded-For` injection is permitted |
| `SIMULATION_KEYCLOAK_BASE_URL` | `http://localhost:8080` | Keycloak server base URL |
| `SIMULATION_KEYCLOAK_REALM` | `aegis-dev` | Keycloak realm name |
| `SIMULATION_KEYCLOAK_CLIENT_ID` | `aegis-local` | Direct Access Grants public client ID |
| `SIMULATION_ALLOW_NON_LOCAL` | `false` | Safeguard override for non-local testbeds |
| `SIMULATION_USER_<NAME>_PASSWORD` | *(none)* | Test credentials for synthetic customer identities |

---

## 4. CLI Usage

The framework provides a Typer-powered command line interface:

### 4.1 Framework Version
```powershell
python -m simulation.cli version
```
*Output:*
```
Aegis Simulation Framework v0.1.0 (Phase 7.2.2 Foundation)
```

### 4.2 Configuration Validation
```powershell
python -m simulation.cli config validate
```
Inspects loaded settings, validates URLs against local isolation rules, and confirms credential masking.

### 4.3 Environment Diagnostic (`doctor`)
```powershell
python -m simulation.cli doctor
```
Performs non-mutating health probes against:
- Aegis Gateway (`/actuator/health/readiness` on `:8000`)
- Keycloak IdP (`/.well-known/openid-configuration` on `:8080`)
- Customer Service (`/actuator/health/readiness` on `:8081`)
- Account Service (`/actuator/health/readiness` on `:8082`)
- Transaction Service (`/actuator/health/readiness` on `:8083`)

### 4.4 Scenario Catalog
```powershell
python -m simulation.cli scenarios list
```
Displays all 9 registered scenario categories and their implementation status (`Planned (Phase 7.2.3)`).

---

## 5. Security & Isolation Rules

1. **Advisory & Experimental Only:** This simulation framework is strictly designed for local FinTech testbeds.
2. **Never Retry Financial POST Operations:** Only safe idempotent methods (`GET`, `HEAD`, `OPTIONS`) are eligible for bounded retries. Non-idempotent operations (such as transfers) are never automatically retried.
3. **No Direct Database Writes:** The simulation interacts exclusively via the public Aegis Gateway; it never writes directly into PostgreSQL or Redis.
4. **Zero Credential / Token Leaks:** Passwords and JWT tokens are excluded from `model_dump()`, string representations, logs, and JSON reports.

---

## 6. Testing

All unit tests use mocked HTTP clients (`respx`) and require no external services:

```powershell
pytest
```
*Result:* 34 passed in ~8s.
