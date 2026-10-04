# Security policy

## Development secrets

Never commit credentials, tokens, private keys, or local environment files. Copy `config/dev.env.example` to `config/dev.env` and replace the example passwords locally. The real file is ignored by Git.

The local stack binds PostgreSQL, Redis, Keycloak, and the synthetic business APIs only to `127.0.0.1`. It is for local development, not production deployment.

## Controlled security work

Aegis security testing and later attack-lab work must target only project-owned services and synthetic data. Do not target external systems.

## Reporting a vulnerability

Do not publish exploitable details in issues. Report findings privately to the repository maintainers with impact, reproduction details, and affected version or commit.
