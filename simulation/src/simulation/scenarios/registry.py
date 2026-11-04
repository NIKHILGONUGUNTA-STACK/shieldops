"""Scenario registry for discovering and listing simulation scenarios."""

from __future__ import annotations

import logging
from typing import Type

from simulation.models import (
    ExpectedOutcome,
    ScenarioCategory,
    ScenarioMetadata,
)
from simulation.scenarios.base import BaseScenario
from simulation.scenarios.benign_customer_flow import BenignCustomerFlow

log = logging.getLogger(__name__)


class ScenarioRegistry:
    """Registry managing scenario metadata and executable classes."""

    def __init__(self) -> None:
        self._metadata_map: dict[str, ScenarioMetadata] = {}
        self._class_map: dict[str, Type[BaseScenario]] = {}

    def register_metadata(self, metadata: ScenarioMetadata) -> None:
        """Registers metadata for a scenario (including planned scenarios)."""
        self._metadata_map[metadata.id] = metadata

    def register_class(self, scenario_cls: Type[BaseScenario], metadata: ScenarioMetadata) -> None:
        """Registers an executable scenario class with its metadata."""
        self._metadata_map[metadata.id] = metadata
        self._class_map[metadata.id] = scenario_cls

    def get_metadata(self, scenario_id: str) -> ScenarioMetadata | None:
        """Retrieves metadata by scenario ID."""
        return self._metadata_map.get(scenario_id)

    def get_class(self, scenario_id: str) -> Type[BaseScenario] | None:
        """Retrieves executable scenario class if registered."""
        return self._class_map.get(scenario_id)

    def list_all(self) -> list[ScenarioMetadata]:
        """Lists all registered scenarios sorted by scenario ID."""
        return sorted(self._metadata_map.values(), key=lambda m: m.id)

    def list_by_category(self, category: ScenarioCategory) -> list[ScenarioMetadata]:
        """Lists scenarios matching a specific category."""
        return [m for m in self.list_all() if m.category == category]


def get_default_registry() -> ScenarioRegistry:
    """Constructs the standard Aegis scenario registry with all planned scenarios."""
    registry = ScenarioRegistry()

    benign_meta = ScenarioMetadata(
        id="SCEN-BENIGN-01",
        name="Legitimate Customer Banking Journey",
        description="Authenticates as legitimate customer, checks account profile, views balances, and executes verified transfer.",
        category=ScenarioCategory.BENIGN,
        target_services=["customer-service", "account-service", "transaction-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[200, 201],
            expected_detection_rules=[],
            expected_incident_severity=None,
        ),
        is_implemented=True,
    )
    registry.register_class(BenignCustomerFlow, benign_meta)

    standard_scenarios = [
        ScenarioMetadata(
            id="SCEN-AUTH-01",
            name="Authentication Failure Burst & Credential Probing",
            description="Sends rapid burst of invalid JWT tokens and malformed credentials targeting account endpoints.",
            category=ScenarioCategory.AUTHENTICATION,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[401],
                expected_detection_rules=["RULE-AUTH-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-AUTHZ-01",
            name="Unauthorized Resource Access & Privilege Escalation",
            description="Customer role attempts to access privileged SOC security APIs and administrative endpoints.",
            category=ScenarioCategory.AUTHORIZATION,
            target_services=["security-gateway"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[403],
                expected_detection_rules=["RULE-AUTH-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-BOLA-01",
            name="Broken Object Level Authorization (BOLA) Cross-Customer Access",
            description="Customer attempts to retrieve and debit accounts belonging to a different customer ID.",
            category=ScenarioCategory.BOLA,
            target_services=["customer-service", "account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[403],
                expected_detection_rules=["RULE-BOLA-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-PROBE-01",
            name="Undocumented API Route Probing & Discovery Traversal",
            description="Probes non-existent admin routes, swagger-ui, debug endpoints, and actuator perimeters.",
            category=ScenarioCategory.PROBING,
            target_services=["external-gateway", "aegis-gateway"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[404],
                expected_detection_rules=["RULE-PROBE-01"],
                expected_incident_severity="LOW",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-INJ-01",
            name="Input Parameter Injection (SQLi & Path Traversal)",
            description="Submits SQL injection strings and traversal sequences in search, query, and reference parameters.",
            category=ScenarioCategory.INJECTION,
            target_services=["customer-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[400, 404],
                expected_detection_rules=["RULE-INJ-01"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-RATE-01",
            name="API Request Burst & Transfer Rate Abuse",
            description="Fires high-frequency burst of transfer requests exceeding threshold within sliding window.",
            category=ScenarioCategory.RATE_ABUSE,
            target_services=["transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 429],
                expected_detection_rules=["RULE-RATE-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-DATA-01",
            name="High-Volume Customer Profile Data Scraping",
            description="Iterates sequentially through predicted UUID and customer ID ranges to scrape data.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 403, 404],
                expected_detection_rules=["RULE-PROBE-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-MULTI-01",
            name="Multi-Vector Coordinated Attack Campaign",
            description="Simulates reconnaissance probing, followed by credential spray, leading into targeted BOLA debit attempt.",
            category=ScenarioCategory.MULTI_VECTOR,
            target_services=["customer-service", "account-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[401, 403, 404],
                expected_detection_rules=["RULE-PROBE-01", "RULE-AUTH-01", "RULE-BOLA-01"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=False,
        ),
    ]

    for meta in standard_scenarios:
        registry.register_metadata(meta)

    return registry

