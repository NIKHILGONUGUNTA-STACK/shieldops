# Phase 1 — Development Environment & Repository Foundation

## Objective

Create a reproducible local foundation for Aegis without implementing the synthetic FinTech application or later security-platform capabilities.

## Built and rationale

The canonical repository layout is in place, with intentional placeholders for future services and platform components. At the Phase 1 baseline, the root Maven parent established Java 21 compilation, `security-intelligence/pyproject.toml` established Python 3.13, and `frontend/package.json` established Node.js 22. Phase 2 updates the Java target to Java 25 and the Python baseline to 3.14 to match the established development toolchain.

Docker Compose provisions a local-only PostgreSQL, Redis, and Keycloak stack. PostgreSQL initializes separate `aegis` and Keycloak databases; Keycloak imports the minimal `aegis-dev` realm. All credentials come from ignored `config/dev.env`; only safe example values are committed. PowerShell scripts provide setup, validation, start, stop, status, and logs operations. GitHub Actions validates the Maven, JSON, Node, and Compose baselines.

## Technology choices and environment model

Java 21/Maven 3.9+, Python 3.13, Node.js 22 LTS, Git, Docker Compose, PostgreSQL, Redis, and Keycloak were the Phase 1 compatibility baseline. Services were localhost-bound and used named Docker volumes. Keycloak waited on PostgreSQL readiness; PostgreSQL and Redis exposed health checks. The Keycloak development client was public only to avoid committing a client secret; production identity configuration was out of scope. The checked local toolchain is Java 25.0.1, Maven 3.9.16, Python 3.14.0, Node.js 22.20.0/npm 10.9.3, Git 2.51.0, Docker 29.1.5, and Compose 5.0.1. Phase 2 uses Java 25 and Python 3.14; it does not downgrade the established toolchain.

## Verification

Static validation includes Compose rendering, JSON parsing, Maven model validation, tool/version inspection, script review, Git ignore rules, and a repository secret scan. Runtime container validation requires a running Docker Desktop daemon.

## Known limitation

This environment has Docker Compose installed but its Docker daemon is unavailable, so containers and live readiness endpoints could not be exercised at the Phase 1 baseline. Java 25 and Python 3.14 are installed locally and are now the Phase 2 targets. The host PowerShell execution policy also blocks direct execution of local `.ps1` files; documented commands use a process-scoped `-ExecutionPolicy Bypass` and do not change machine policy.

## Exit condition and status

Phase 1 exited when the committed canonical foundation was statically valid and a developer could start the three local dependencies using the documented commands. The project status at that phase boundary was **Phase 1 complete**; the later Phase 2 implementation is recorded separately.

## Runtime verification

On 2026-10-01, `scripts/validate-dev.ps1` successfully ran Compose configuration validation with the explicit ignored `config/dev.env`, followed by `docker compose ... up -d postgres redis keycloak` and `docker compose ... ps`. PostgreSQL, Redis, and Keycloak all reached `healthy`. Direct Compose commands must include `--env-file config/dev.env`; Compose does not discover this file under `config/` automatically. The local machine already had PostgreSQL listening on port 5432, so the ignored local env file maps the Aegis PostgreSQL port to 5433; the committed template retains the default 5432. The first runtime check also exposed that the PostgreSQL service was not passing `POSTGRES_KEYCLOAK_DB` into its init script; Compose now passes this setting, and the existing volume was retained while the Keycloak database was initialized.
