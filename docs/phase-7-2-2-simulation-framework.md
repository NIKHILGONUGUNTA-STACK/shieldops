# Aegis Phase 7.2.2 — Python Simulation Framework Foundation

**Document Version:** 1.0.0  
**Status:** Completed & Verified  
**Date:** 2026-11-03  
**Implementation Directory:** `simulation/`  
**Test Suite:** `simulation/tests/` (34 passing unit tests)

---

## 1. Executive Summary & Architectural Scope

Phase 7.2.2 establishes the foundational Python simulation framework for the Aegis FinTech security testbed. Building upon the Phase 7.2.1 OpenAPI contract baseline, this framework provides the client infrastructure, authentication lifecycle management, scenario abstractions, and diagnostic reporting required to drive synthetic traffic and controlled attack scenarios through the Aegis Gateway in Phase 7.2.3.

### Strict Scope Boundary
In strict adherence to Phase 7.2.2 guidelines:
- **No live business API traffic** or synthetic transactions were generated.
- **No database records** (customers, accounts, beneficiaries) were mutated or seeded.
- **No attack payloads** or adversary workflows were executed against live services.
- All 9 scenario categories are defined as structured metadata and marked as `Planned (Phase 7.2.3)`.

---

## 2. Technology Stack & Packaging

The simulation framework is implemented in modern Python with strict typing and standard packaging:

| Technology | Version / Requirement | Role in Framework |
| :--- | :--- | :--- |
| **Python** | `>=3.11` (Tested on `3.14.0`) | Language runtime |
| **HTTPX** | `>=0.27.0` | Asynchronous HTTP client engine |
| **Pydantic** | `>=2.7.0` | Typed domain, configuration, and scenario models |
| **Pydantic-Settings** | `>=2.2.0` | Environment variable parsing and validation |
| **Typer** | `>=0.12.0` | Command line interface application |
| **Rich** | `>=13.7.0` | Monospace tables, diagnostic panels, and terminal rendering |
| **PyYAML** | `>=6.0.1` | YAML configuration file parsing |
| **python-dotenv** | `>=1.0.1` | Local `.env` file loading |
| **pytest & pytest-asyncio** | `>=8.2.0` / `>=0.23.0` | Test framework with asynchronous test support |
| **respx** | `>=0.21.0` | Declarative HTTP request mocking for offline unit testing |

Packaging is defined via standard `simulation/pyproject.toml` with editable install support (`pip install -e ".[dev]"`).

---

## 3. Core Modules & Implementation Details

### 3.1 Configuration Management (`simulation/src/simulation/config.py`)
- **Pydantic v2 Models:** `GatewayConfig`, `KeycloakConfig`, `DownstreamHealthConfig`, `ExecutionConfig`, and `SimulationConfig`.
- **Precedence Hierarchy:**
  1. Environment variables (`SIMULATION_*`)
  2. Local `.env` file variables
  3. YAML configuration file (`config/default.yaml`)
  4. Typed model defaults
- **Local Isolation Safeguards:** Enforces that all target URLs (`gateway.base_url`, `keycloak.base_url`, downstream services) resolve strictly to localhost (`localhost`, `127.0.0.1`, `::1`). Any non-local hostname raises a `ValueError` unless `execution.allow_non_local: true` is explicitly configured.
- **Credential Masking:** Passwords loaded from `SIMULATION_USER_*_PASSWORD` are excluded from model dumps, JSON outputs, and string representations.

### 3.2 Keycloak Authentication Manager (`simulation/src/simulation/auth/keycloak.py`)
- **Direct Access Grants:** Implements Resource Owner Password Credentials Grant (`grant_type=password`) using the existing `aegis-dev` realm and `aegis-local` public client.
- **Token Model (`KeycloakToken`):** Stores `access_token`, `expires_in`, `refresh_token`, and acquisition timestamp.
- **In-Memory Caching & Renewal:** Checks token validity with a configurable buffer window (`token_expiry_buffer_seconds: 30`). Automatically triggers refresh token grant or re-authentication before expiration.
- **Multi-Identity Support:** Maintains an in-memory cache keyed by normalized identity (`alex.morgan`, `sam.taylor`, `analyst`, `admin`).
- **Defensive Invariant:** JWT tokens and passwords are masked with `***[REDACTED]***` in all `__repr__` and `__str__` outputs.

### 3.3 Gateway Async HTTP Client (`simulation/src/simulation/clients/gateway.py`)
- **Asynchronous Execution:** Built on `httpx.AsyncClient` supporting concurrency and configurable timeouts.
- **Correlation ID Tracking:** Injects a unique UUID `X-Correlation-Id` into every outbound request unless explicitly provided.
- **Duration Instrumentation:** Measures round-trip request duration in milliseconds (`duration_ms`).
- **Strict Retry Invariant:**
  - Safe idempotent methods (`GET`, `HEAD`, `OPTIONS`) are permitted bounded retries (up to `max_retries`) on transient 502/503/504 errors.
  - Non-idempotent operations (`POST`, `PUT`, `DELETE`, `PATCH`) are **never** automatically retried without an explicit idempotency strategy.
- **Synthetic Source IP Safety:**
  - Evaluated existing gateway `TelemetryFilter.java` proxy behavior.
  - Injecting `X-Forwarded-For` is **disabled by default** (`allow_synthetic_source_ip: false`). Attempting to inject a synthetic IP without explicit configuration raises a `GatewayClientError`.

### 3.4 Scenario Framework & Default Registry (`simulation/src/simulation/scenarios/`)
- **Abstract Base (`BaseScenario`):** Provides structured lifecycle execution, error trapping, and summary generation.
- **Category Support:** Enumerates all 9 planned testbed vectors:
  1. `BENIGN`: Legitimate Customer Banking Flow
  2. `AUTHENTICATION`: Credential Stuffing & Auth Burst
  3. `AUTHORIZATION`: Unauthorized Resource Access & Privilege Escalation
  4. `BOLA`: Broken Object Level Authorization Cross-Customer Access
  5. `PROBING`: Shadow API & Directory Probing
  6. `INJECTION`: SQLi & Path Traversal Injection
  7. `RATE_ABUSE`: Transaction Request Burst Rate Abuse
  8. `DATA_ACCESS`: High-Volume Profile Scraping
  9. `MULTI_VECTOR`: Multi-Vector Coordinated Campaign
- **Registry (`ScenarioRegistry`):** Pre-registers metadata for all 9 scenarios, clearly identifying them as `Planned (Phase 7.2.3)`.

### 3.5 Execution Reporting (`simulation/src/simulation/reporting/reporter.py`)
- **Metrics Aggregation:** Tracks total requests, success/failure counts, HTTP status code distributions, and execution durations.
- **Leak-Proof JSON Serialization:** Evaluates serialized reports against forbidden credential markers (`bearer `, `eyjh`, `password`, `client_secret`), raising a safety violation if sensitive tokens are detected.

### 3.6 Command Line Interface (`simulation/src/simulation/cli.py`)
- `aegis-sim version`: Displays framework version and active phase.
- `aegis-sim config validate`: Validates configuration parameters and confirms local isolation safeguards.
- `aegis-sim doctor`: Executes non-mutating health probes against Gateway, Keycloak, and downstream microservices with ASCII-safe status indicators.
- `aegis-sim scenarios list`: Displays catalog of registered scenario categories and implementation status.

---

## 4. Verification & Automated Test Coverage

The framework is verified by 34 automated unit tests running with `pytest` and `respx`:

```
============================= test session starts =============================
simulation/tests/test_auth.py .......                                   [ 20%]
simulation/tests/test_cli.py ......                                     [ 38%]
simulation/tests/test_config.py .......                                 [ 58%]
simulation/tests/test_gateway_client.py ........                        [ 82%]
simulation/tests/test_scenario_models.py ......                         [100%]
============================== 34 passed in 8.68s ==============================
```

### Coverage Highlights:
- **`test_config.py` (7 tests):** Default parameters, non-local URL rejection, non-local override flag, invalid URL syntax, environment overrides, YAML configuration loading.
- **`test_auth.py` (7 tests):** Direct Access Grant token acquisition, cache hits, token expiration renewal, refresh grant, invalid credentials (400), client authentication failure (401), connection errors, token masking, cache invalidation.
- **`test_gateway_client.py` (8 tests):** Correlation ID injection, bearer auth headers, non-retry of POST operations, transient GET 502 retries, retry exhaustion, timeout exceptions, synthetic source IP prevention when disabled, synthetic IP injection when permitted, custom correlation ID preservation.
- **`test_scenario_models.py` (6 tests):** Request recording, registry category coverage (all 9 categories), lifecycle trapping of planned scenarios, execution success lifecycle, JSON report serialization, sensitive token leak prevention.
- **`test_cli.py` (6 tests):** Version command, config validate command, bad config exit code 1, scenarios list command, doctor all healthy, doctor unreachable service diagnostic.

---

## 5. Next Steps

With the Python simulation foundation in place:
- **Phase 7.2.3:** Implementation of executable scenario workflows (legitimate customer journeys, BOLA attacks, injection bursts) driving live traffic through the Aegis Gateway to validate threat detection and posture evaluation.

