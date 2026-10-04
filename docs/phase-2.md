# Phase 2 — Synthetic FinTech Application

## Scope and architecture

Phase 2 adds three independently deployable Spring Boot services to the verified Phase 1 PostgreSQL, Redis, and Keycloak environment. Customer, account, and transaction services use separate PostgreSQL schemas and Flyway migrations. The APIs map persistence records into response DTOs. Controllers expose HTTP contracts, repositories persist records, and services enforce account debit rules. Money uses PostgreSQL `DECIMAL(19,4)` and Java `BigDecimal`. Seed data and all beneficiary destinations are synthetic. Keycloak authentication, risk scoring, and external bank settlement are outside this phase.

Customer Service provides `GET /customers/{id}` and `/profile`. Account Service provides account list/detail/balance and `POST /accounts/{id}/debits` for the internal transaction-to-account contract. Transaction Service provides beneficiary create/list/get/verify, transaction list/get, and `POST /transfers`.

The primary workflow is customer profile → account detail (composed from Customer Service) → beneficiary create and verify → transfer → transaction completion. Transfers validate customer ownership, beneficiary verification, account status, matching currencies, and available funds. Account Service locks the source account row and commits its balance reduction with a unique debit-ledger entry in one database transaction. Transaction status progresses through `CREATED`, `PENDING`, `AUTHORIZED`, and `COMPLETED`. The idempotency reference is shared with the debit ledger, so retrying after an ambiguous service response cannot debit twice. A completed transaction means a synthetic outgoing posting was recorded locally; no external recipient is credited and no bank settlement is asserted.

## Run locally

Create `config/dev.env` from `config/dev.env.example`, replace local passwords, and use the scripts below. `config/dev.env` is ignored by Git; keep the example file as the committed template. `start-dev.ps1` validates Compose with `config` before it starts the stack. Service host ports default to 8081, 8082, and 8083; all bind to loopback.

```powershell
Copy-Item config/dev.env.example config/dev.env
# Edit config/dev.env and set unique local passwords before startup.
./scripts/validate-dev.ps1
docker compose --env-file config/dev.env -f infrastructure/docker/compose.yml config
./scripts/start-dev.ps1
docker compose --env-file config/dev.env -f infrastructure/docker/compose.yml ps
mvn --batch-mode --no-transfer-progress package
```

Run `docker compose ... ps` and confirm every service reports healthy before treating runtime verification as complete. Readiness endpoints are `/actuator/health/readiness` on application services. Keycloak exposes health on its management port. The seeded customer is `10000000-0000-4000-8000-000000000001`; the seeded USD account is `20000000-0000-4000-8000-000000000001` with initial balance `12500.0000`.

## Phase 2 exit checklist

- [x] Three independently deployable services and separate schemas/migrations.
- [x] Customer profile and account detail composition across service HTTP contracts.
- [x] Beneficiary create and verify, followed by completed synthetic transfer.
- [x] Ownership, verified-beneficiary, active-account, currency, and funds validation.
- [x] Exact decimal representation, atomic local debit ledger, and idempotent references.
- [x] Customer and transaction HTTP responses use DTOs; account debit rules are isolated in a service and repositories own persistence.
- [x] Unit tests cover decimal and transaction state rules, beneficiary validation, controller composition, and debit idempotency. Live Compose smoke verification exercises the HTTP-to-database workflow.
- [ ] Dedicated automated repository tests and HTTP API tests for success, validation, not-found, invalid state, and persistence.
- [x] Compose configuration and container health verified after actual startup.
- [x] Developer run steps and security boundaries documented.

This phase does not implement authentication integration, external settlement, fraud/risk intelligence, the attack lab, or production deployment. Database workflow verification was performed against the running Compose stack, but it does not replace the missing automated repository and API test suites. Transaction orchestration still resides in its controller, and consistent centralized error handling has not yet been applied to every service. **Phase 2 exit status: implementation and runtime verified; exit condition remains incomplete pending the automated persistence/API tests and remaining API-boundary cleanup.** Phase 3 remains outside the current implementation request.
