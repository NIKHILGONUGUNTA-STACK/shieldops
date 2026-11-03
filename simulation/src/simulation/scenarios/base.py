"""Base scenario abstraction for Aegis traffic simulation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import (
    ExecutionStatus,
    ScenarioMetadata,
    ScenarioSummary,
)

log = logging.getLogger(__name__)


class BaseScenario(ABC):
    """Abstract base class for all simulation workflows and attack scenarios."""

    def __init__(
        self,
        metadata: ScenarioMetadata,
        config: SimulationConfig,
    ) -> None:
        self.metadata = metadata
        self.config = config

    @property
    def id(self) -> str:
        return self.metadata.id

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def category(self) -> str:
        return self.metadata.category.value

    @abstractmethod
    async def execute(
        self,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
    ) -> ScenarioSummary:
        """Executes the scenario logic using the provided gateway client and auth manager.

        Subclasses in Phase 7.2.3 will implement specific traffic steps.
        """
        raise NotImplementedError("Scenario execution logic is implemented in Phase 7.2.3")

    async def run(
        self,
        gateway: GatewayClient,
        auth: KeycloakAuthManager,
    ) -> ScenarioSummary:
        """Runs the scenario with safe error trapping and lifecycle timing."""
        summary = ScenarioSummary(
            scenario_id=self.metadata.id,
            category=self.metadata.category,
            status=ExecutionStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            expected_detection_rules=self.metadata.expected_outcome.expected_detection_rules,
        )

        log.info("Starting execution of scenario %s (%s)", self.metadata.id, self.metadata.name)

        try:
            summary = await self.execute(gateway, auth)
            summary.status = ExecutionStatus.SUCCESS
        except NotImplementedError as e:
            summary.status = ExecutionStatus.PLANNED
            summary.execution_errors.append(str(e))
            log.info("Scenario %s is planned but not yet implemented", self.metadata.id)
        except Exception as e:
            summary.status = ExecutionStatus.FAILURE
            summary.execution_errors.append(f"{type(e).__name__}: {e}")
            log.error("Execution failed for scenario %s: %s", self.metadata.id, e, exc_info=True)
        finally:
            summary.finished_at = datetime.now(timezone.utc)

        return summary

