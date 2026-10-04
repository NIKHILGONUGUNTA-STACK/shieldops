# Aegis — Adaptive Enterprise API Defense Platform

Aegis is a controlled, enterprise-inspired API defense platform. **Phase 1: Development Environment & Repository Foundation** is complete. Phase 2 has a running synthetic FinTech application; its automated repository and API test coverage remains incomplete. Security intelligence, attack lab, dashboard, Kafka, Kubernetes, and production deployment remain out of scope.

## Development prerequisites

- Java 25.0.1 and Maven 3.9.16+
- Node.js 22 LTS
- Python 3.14+
- Git
- Docker Desktop with Docker Compose

## Quick start

In PowerShell from the repository root (the `-ExecutionPolicy Bypass` flag is useful on systems that prohibit locally unsigned scripts):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/setup-dev.ps1
# Edit config/dev.env and replace the example password values.
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/validate-dev.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/start-dev.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/status-dev.ps1
```

The scripts pass the ignored `config/dev.env` explicitly to Compose. Direct Compose commands must do the same because Compose does not automatically load files from `config/`:

```powershell
docker compose --env-file config/dev.env -f infrastructure/docker/compose.yml config
docker compose --env-file config/dev.env -f infrastructure/docker/compose.yml up -d
docker compose --env-file config/dev.env -f infrastructure/docker/compose.yml ps
```

The local endpoints are PostgreSQL at `127.0.0.1:${POSTGRES_PORT}` (5432 by default), Redis at `127.0.0.1:6379`, Keycloak at `http://127.0.0.1:8080`, and its management endpoint at `127.0.0.1:9000`. The imported realm is `aegis-dev`; its `aegis-local` client is deliberately public for local browser development only.

Stop the stack with `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/stop-dev.ps1`. Add `-RemoveVolumes` only when intentionally discarding local database and Redis data.

## Repository layout

The canonical layout is preserved: `services/` (customer, account, transaction), `gateway/`, `security-intelligence/`, `frontend/`, `attack-lab/`, `infrastructure/docker/`, `config/`, `keycloak/`, `scripts/`, `docs/`, and `.github/workflows/`. Phase 2 implements the customer, account, and transaction services; remaining component directories retain their phase boundaries.

See [the Phase 1 record](docs/phase-1.md) and [the Phase 2 record](docs/phase-2.md) for scope, verification, and phase boundaries.
