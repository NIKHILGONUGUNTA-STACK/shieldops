"""Scenario execution framework and registry."""

from simulation.scenarios.base import BaseScenario
from simulation.scenarios.benign_customer_flow import BenignCustomerFlow
from simulation.scenarios.registry import ScenarioRegistry, get_default_registry
from simulation.scenarios.soc_verifier import (
    SocTelemetryVerifier,
    SocVerificationResult,
    VerificationOutcome,
)

__all__ = [
    "BaseScenario",
    "BenignCustomerFlow",
    "ScenarioRegistry",
    "SocTelemetryVerifier",
    "SocVerificationResult",
    "VerificationOutcome",
    "get_default_registry",
]

