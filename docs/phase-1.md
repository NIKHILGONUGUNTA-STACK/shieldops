# Phase 1 — Development Environment & Repository Foundation

## Objective

Create a reproducible local foundation for Aegis without implementing the synthetic FinTech application or later security-platform capabilities.

## Built and rationale

The canonical repository layout is in place, with intentional placeholders for future services and platform components. A root Maven parent establishes Java 21 compilation, `security-intelligence/pyproject.toml` establishes Python 3.13, and `frontend/package.json` establishes Node.js 22. This keeps later work aligned without creating business code.

Docker Compose provisions a local-only PostgreSQL, Redis, and Keycloak stack. PostgreSQL initializes separate `aegis` and Keycloak databases; Keycloak imports the minimal `aegis-dev` realm. All credentials come from ignored `config/dev.env`; only safe example values are committed. PowerShell scripts provide setup, validation, start, stop, status, and logs operations. GitHub Actions validates the Maven, JSON, Node, and Compose baselines.

## Technology choices and environment model

Java 21/Maven 3.9+, Python 3.13, Node.js 22 LTS, Git, Docker Compose, PostgreSQL, Redis, and Keycloak are the Phase 1 baseline. Services are localhost-bound and use named Docker volumes. Keycloak waits on PostgreSQL readiness; PostgreSQL and Redis expose health checks. The Keycloak development client is public only to avoid committing a client secret; production identity configuration is explicitly out of scope.

## Verification

Static validation includes Compose rendering, JSON parsing, Maven model validation, tool/version inspection, script review, Git ignore rules, and a repository secret scan. Runtime container validation requires a running Docker Desktop daemon.

## Known limitation

This environment has Docker Compose installed but its Docker daemon is unavailable, so containers and live readiness endpoints could not be exercised here. The available JDK is 25 rather than the required Java 21 target, and Python 3.13 is not installed in this environment. CI pins the requested Java, Node, and Python baselines. The host PowerShell execution policy also blocks direct execution of local `.ps1` files; documented commands use a process-scoped `-ExecutionPolicy Bypass` and do not change machine policy.

## Exit condition and status

Phase 1 exits when the committed canonical foundation is statically valid and a developer can start the three local dependencies using the documented commands. Static validation is complete; runtime confirmation remains the developer's local Docker Desktop check. The current project status is **Phase 1 complete**. Phase 2 is next and has not been started.
