"""Tests for scenario models, registry, base class, and reporter."""

from datetime import datetime, timezone
import json
import pytest

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import GatewayConfig, KeycloakConfig, SimulationConfig
from simulation.models import (
    ExecutionStatus,
    ExpectedOutcome,
    RequestResult,
    ScenarioCategory,
    ScenarioMetadata,
    ScenarioSummary,
)
from simulation.reporting.reporter import ScenarioReporter
from simulation.scenarios.base import BaseScenario
from simulation.scenarios.registry import ScenarioRegistry, get_default_registry


def test_scenario_summary_request_recording():
    summary = ScenarioSummary(
        scenario_id="SCEN-TEST-01",
        category=ScenarioCategory.BENIGN,
        status=ExecutionStatus.RUNNING,
    )

    r1 = RequestResult(
        correlation_id="cid-1",
        http_method="GET",
        url="http://localhost:8000/api/v1/customers",
        status_code=200,
        duration_ms=45.2,
        is_success=True,
    )
    r2 = RequestResult(
        correlation_id="cid-2",
        http_method="GET",
        url="http://localhost:8000/api/v1/accounts/missing",
        status_code=404,
        duration_ms=22.1,
        is_success=False,
    )

    summary.record_request(r1)
    summary.record_request(r2)

    assert summary.total_requests == 2
    assert summary.successful_requests == 1
    assert summary.failed_requests == 1
    assert summary.status_distribution == {200: 1, 404: 1}


def test_default_registry_all_categories_present():
    registry = get_default_registry()
    scenarios = registry.list_all()

    assert len(scenarios) >= 9

    # Verify all 9 standard categories are covered
    categories = {s.category for s in scenarios}
    expected_categories = {
        ScenarioCategory.BENIGN,
        ScenarioCategory.AUTHENTICATION,
        ScenarioCategory.AUTHORIZATION,
        ScenarioCategory.BOLA,
        ScenarioCategory.PROBING,
        ScenarioCategory.INJECTION,
        ScenarioCategory.RATE_ABUSE,
        ScenarioCategory.DATA_ACCESS,
        ScenarioCategory.MULTI_VECTOR,
    }
    assert categories == expected_categories

    # Verify implemented scenarios
    implemented_ids = {
        "SCEN-BENIGN-01",
        "SCEN-BOLA-01",
        "SCEN-BOLA-02",
        "SCEN-DATA-LEAK-01",
        "SCEN-BULK-EXTRACT-01",
        "SCEN-EXFIL-01",
        "SCEN-BENIGN-02",
    }
    benign = registry.get_metadata("SCEN-BENIGN-01")
    assert benign is not None and benign.is_implemented is True
    assert registry.get_class("SCEN-BENIGN-01") is not None
    assert all(not s.is_implemented for s in scenarios if s.id not in implemented_ids)

    # Category lookup
    bola_scenarios = registry.list_by_category(ScenarioCategory.BOLA)
    assert len(bola_scenarios) >= 1
    assert any(s.id == "SCEN-BOLA-01" for s in bola_scenarios)


@pytest.mark.asyncio
async def test_base_scenario_lifecycle_planned():
    class DummyPlannedScenario(BaseScenario):
        async def execute(self, gateway, auth):
            return await super().execute(gateway, auth)

    meta = ScenarioMetadata(
        id="SCEN-DUMMY-01",
        name="Dummy Planned Scenario",
        description="Testing base execution",
        category=ScenarioCategory.PROBING,
    )
    config = SimulationConfig()
    scenario = DummyPlannedScenario(meta, config)

    gateway = GatewayClient(config.gateway)
    auth = KeycloakAuthManager(config.keycloak)
    try:
        summary = await scenario.run(gateway, auth)
        assert summary.status == ExecutionStatus.PLANNED
        assert len(summary.execution_errors) == 1
        assert "Phase 7.2.3" in summary.execution_errors[0]
        assert summary.finished_at is not None
    finally:
        await gateway.aclose()
        await auth.aclose()


@pytest.mark.asyncio
async def test_base_scenario_lifecycle_success():
    class DummyWorkingScenario(BaseScenario):
        async def execute(self, gateway, auth):
            summary = ScenarioSummary(
                scenario_id=self.metadata.id,
                category=self.metadata.category,
                status=ExecutionStatus.RUNNING,
            )
            summary.record_request(
                RequestResult(
                    correlation_id="c1",
                    http_method="GET",
                    url="http://localhost:8000/health",
                    status_code=200,
                    duration_ms=10.0,
                    is_success=True,
                )
            )
            return summary

    meta = ScenarioMetadata(
        id="SCEN-WORK-01",
        name="Dummy Working Scenario",
        description="Testing successful execution",
        category=ScenarioCategory.BENIGN,
    )
    config = SimulationConfig()
    scenario = DummyWorkingScenario(meta, config)

    gateway = GatewayClient(config.gateway)
    auth = KeycloakAuthManager(config.keycloak)
    try:
        summary = await scenario.run(gateway, auth)
        assert summary.status == ExecutionStatus.SUCCESS
        assert summary.total_requests == 1
        assert summary.successful_requests == 1
    finally:
        await gateway.aclose()
        await auth.aclose()


def test_scenario_reporter_json_and_redaction():
    reporter = ScenarioReporter(environment_id="test-run")

    s1 = ScenarioSummary(
        scenario_id="SCEN-1",
        category=ScenarioCategory.BENIGN,
        status=ExecutionStatus.SUCCESS,
        total_requests=3,
        successful_requests=3,
        status_distribution={200: 3},
    )
    s2 = ScenarioSummary(
        scenario_id="SCEN-2",
        category=ScenarioCategory.BOLA,
        status=ExecutionStatus.FAILURE,
        total_requests=2,
        failed_requests=2,
        status_distribution={403: 2},
        execution_errors=["Access forbidden"],
    )

    reporter.record_scenario(s1)
    reporter.record_scenario(s2)

    report_json = reporter.to_json()
    parsed = json.loads(report_json)

    assert parsed["environment_id"] == "test-run"
    assert parsed["total_scenarios"] == 2
    assert parsed["scenarios_passed"] == 1
    assert parsed["scenarios_failed"] == 1
    assert parsed["total_requests"] == 5
    assert parsed["overall_status_distribution"] == {"200": 3, "403": 2}


def test_scenario_reporter_prevents_token_leak():
    reporter = ScenarioReporter(environment_id="leak-test")
    # Inadvertent token leak in error text
    leaky_summary = ScenarioSummary(
        scenario_id="SCEN-LEAK",
        category=ScenarioCategory.AUTHENTICATION,
        status=ExecutionStatus.FAILURE,
        execution_errors=["Failed with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"],
    )
    reporter.record_scenario(leaky_summary)

    with pytest.raises(ValueError) as exc_info:
        reporter.to_json()
    assert "Safety Violation" in str(exc_info.value)

