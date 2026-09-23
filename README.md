# Aegis — Adaptive Enterprise API Defense Platform

Aegis is a controlled, enterprise-inspired API defense platform. The current repository state is **Phase 1: Development Environment & Repository Foundation**. No FinTech business services, security intelligence, attack lab, dashboard, Kafka, Kubernetes, or production deployment are implemented yet.

## Development prerequisites

- Java 21 (the project target; Maven 3.9+)
- Node.js 22 LTS
- Python 3.13
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

The local endpoints are PostgreSQL at `127.0.0.1:5432`, Redis at `127.0.0.1:6379`, Keycloak at `http://127.0.0.1:8080`, and its management endpoint at `127.0.0.1:9000`. The imported realm is `aegis-dev`; its `aegis-local` client is deliberately public for local browser development only.

Stop the stack with `powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/stop-dev.ps1`. Add `-RemoveVolumes` only when intentionally discarding local database and Redis data.

## Repository layout

The canonical layout is preserved: `services/` (customer, account, transaction), `gateway/`, `security-intelligence/`, `frontend/`, `attack-lab/`, `infrastructure/docker/`, `config/`, `keycloak/`, `scripts/`, `docs/`, and `.github/workflows/`. Empty component directories are intentional Phase 1 placeholders, not application implementations.

See [the Phase 1 record](docs/phase-1.md) for scope, verification, and the phase exit condition.
