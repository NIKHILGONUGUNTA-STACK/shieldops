# Aegis FinTech Simulation Framework

The Aegis Simulation Framework is a modular Python package designed to generate realistic FinTech banking workflows and controlled security attack scenarios against the Aegis Security Gateway and threat detection engine.

## Status

**Current Phase:** Phase 7.2.2 — Framework Foundation (Architecture & Infrastructure)  
**Traffic Generation:** Not active (Planned for Phase 7.2.3)

## Architecture Overview

```
simulation/
├── pyproject.toml          # Project metadata and dependencies
├── .env.example            # Environment variable template
├── config/
│   └── default.yaml        # Default local testbed configuration
├── src/simulation/
│   ├── auth/               # Keycloak OIDC authentication manager
│   ├── clients/            # Gateway async HTTPX client
│   ├── scenarios/          # Scenario models, base class & registry
│   ├── reporting/          # Execution metrics & JSON reporting
│   ├── config.py           # Pydantic v2 configuration models
│   ├── models.py           # Core domain & scenario models
│   └── cli.py              # Typer CLI interface
└── tests/                  # Pytest unit tests (100% mocked)
```

## Quick Start

```powershell
# Setup virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install in editable mode with development dependencies
pip install -e ".[dev]"

# Run CLI diagnostic
python -m simulation.cli doctor

# Run CLI configuration check
python -m simulation.cli config validate

# Run test suite
pytest
```

