#!/usr/bin/env python3
"""Standalone runner entry point for Aegis ShieldOps API Security CI Gate."""

import sys
from pathlib import Path

# Ensure simulation/src is available on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SIM_SRC = PROJECT_ROOT / "simulation" / "src"
if SIM_SRC.exists() and str(SIM_SRC) not in sys.path:
    sys.path.insert(0, str(SIM_SRC))

from simulation.ci_gate.cli import app

if __name__ == "__main__":
    app()
