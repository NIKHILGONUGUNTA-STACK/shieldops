"""Tests for Data Leakage, BOLA Detection scenarios, and Research Evaluation."""

import httpx
import pytest
import respx

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import ExecutionStatus
from simulation.reporting.evaluation import (
    BenchmarkEvaluator,
    ClassificationResult,
    GroundTruthLabel,
)
from simulation.scenarios.benign_repeated_reads_scenario import BenignRepeatedReadsScenario
from simulation.scenarios.bola_scenarios import (
    BolaAttemptScenario,
    BolaProbeCampaignScenario,
)
from simulation.scenarios.data_leak_scenarios import (
    BulkExtractScenario,
    DataLeakScenario,
    MultiStageExfilScenario,
)
from simulation.scenarios.registry import get_default_registry


@pytest.fixture
def mock_config():
    return SimulationConfig(
        gateway={"base_url": "http://localhost:8000"},
        keycloak={"base_url": "http://localhost:8080", "realm": "aegis-dev", "client_id": "aegis-local"},
        execution={"environment_id": "local-dev"},
        benign_flow={
            "transfer_amount": 25.0,
            "transfer_currency": "USD",
            "alex_customer_id": "10000000-0000-4000-8000-000000000001",
            "sam_customer_id": "10000000-0000-4000-8000-000000000002",
        },
        user_passwords={
            "alex_morgan": "secret-alex",
            "sam_taylor": "secret-sam",
            "analyst": "secret-analyst",
        },
    )


def setup_auth_mock(respx_mock):
    token_url = "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token"
    respx_mock.post(token_url).mock(
        return_value=httpx.Response(200, json={"access_token": "mock-alex-jwt", "expires_in": 300})
    )


def test_scenario_registry_contains_all_seven_scenarios():
    registry = get_default_registry()
    all_scenarios = registry.list_all()
    scenario_ids = [s.id for s in all_scenarios]

    expected_ids = [
        "SCEN-BENIGN-01",
        "SCEN-BOLA-01",
        "SCEN-BOLA-02",
        "SCEN-DATA-LEAK-01",
        "SCEN-BULK-EXTRACT-01",
        "SCEN-EXFIL-01",
        "SCEN-BENIGN-02",
    ]

    for expected_id in expected_ids:
        assert expected_id in scenario_ids, f"Scenario {expected_id} missing from registry"
        meta = registry.get_metadata(expected_id)
        assert meta is not None
        assert meta.is_implemented is True
        scenario_cls = registry.get_class(expected_id)
        assert scenario_cls is not None, f"Scenario class for {expected_id} not registered"


@respx.mock
@pytest.mark.asyncio
async def test_bola_attempt_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001").mock(
        return_value=httpx.Response(200, json={"id": "10000000-0000-4000-8000-000000000001", "name": "Alex"})
    )
    respx.get("http://localhost:8000/api/v1/customers/20000000-0000-4000-8000-000000000002").mock(
        return_value=httpx.Response(403, json={"title": "Forbidden", "status": 403, "detail": "BOLA access denied"})
    )
    respx.get("http://localhost:8000/api/v1/accounts/30000000-0000-4000-8000-000000000003").mock(
        return_value=httpx.Response(403, json={"title": "Forbidden", "status": 403, "detail": "BOLA access denied"})
    )

    registry = get_default_registry()
    meta = registry.get_metadata("SCEN-BOLA-01")
    scenario_cls = registry.get_class("SCEN-BOLA-01")

    scenario = scenario_cls(meta, mock_config)
    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3
    assert summary.status_distribution.get(403) == 2
    assert summary.status_distribution.get(200) == 1
    assert summary.run_manifest is not None
    assert summary.run_manifest.requests[1].normalized_route == "/api/v1/customers/{id}"


@respx.mock
@pytest.mark.asyncio
async def test_bola_probe_campaign_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/accounts/acc-victim-001").mock(return_value=httpx.Response(403))
    respx.get("http://localhost:8000/api/v1/accounts/acc-victim-002").mock(return_value=httpx.Response(403))
    respx.get("http://localhost:8000/api/v1/accounts/acc-victim-003").mock(return_value=httpx.Response(403))

    registry = get_default_registry()
    meta = registry.get_metadata("SCEN-BOLA-02")
    scenario_cls = registry.get_class("SCEN-BOLA-02")

    scenario = scenario_cls(meta, mock_config)
    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3
    assert summary.status_distribution.get(403) == 3


@respx.mock
@pytest.mark.asyncio
async def test_bulk_extract_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/cust-harv-.*").mock(
        return_value=httpx.Response(200, json={"data": "harvested"})
    )

    registry = get_default_registry()
    meta = registry.get_metadata("SCEN-BULK-EXTRACT-01")
    scenario_cls = registry.get_class("SCEN-BULK-EXTRACT-01")

    scenario = scenario_cls(meta, mock_config)
    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 4
    assert summary.status_distribution.get(200) == 4


@respx.mock
@pytest.mark.asyncio
async def test_multi_stage_exfil_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/actuator/env").mock(return_value=httpx.Response(404))
    respx.get("http://localhost:8000/api/v1/admin/internal").mock(return_value=httpx.Response(404))
    respx.get("http://localhost:8000/api/v1/swagger-config").mock(return_value=httpx.Response(404))
    respx.get("http://localhost:8000/api/v1/accounts/acc-probe-x1").mock(return_value=httpx.Response(403))
    respx.get("http://localhost:8000/api/v1/accounts/acc-probe-x2").mock(return_value=httpx.Response(403))
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/cust-harvest-.*").mock(
        return_value=httpx.Response(200, json={"profile": "data"})
    )

    registry = get_default_registry()
    meta = registry.get_metadata("SCEN-EXFIL-01")
    scenario_cls = registry.get_class("SCEN-EXFIL-01")

    scenario = scenario_cls(meta, mock_config)
    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 8
    assert summary.status_distribution.get(404) == 3
    assert summary.status_distribution.get(403) == 2
    assert summary.status_distribution.get(200) == 3


@respx.mock
@pytest.mark.asyncio
async def test_benign_repeated_reads_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(
        return_value=httpx.Response(200, json={"id": "self", "status": "ACTIVE"})
    )
    respx.get("http://localhost:8000/api/v1/accounts").mock(
        return_value=httpx.Response(200, json=[{"id": "acc-self"}])
    )

    registry = get_default_registry()
    meta = registry.get_metadata("SCEN-BENIGN-02")
    scenario_cls = registry.get_class("SCEN-BENIGN-02")

    scenario = scenario_cls(meta, mock_config, repetitions=3)
    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 6
    assert summary.status_distribution.get(200) == 6


def test_research_evaluation_metrics_calculation():
    evals = [
        BenchmarkEvaluator.evaluate_scenario("SCEN-BENIGN-01", "Benign Flow", GroundTruthLabel.BENIGN, [], []),
        BenchmarkEvaluator.evaluate_scenario("SCEN-BENIGN-02", "Benign Reads", GroundTruthLabel.BENIGN, [], []),
        BenchmarkEvaluator.evaluate_scenario("SCEN-BOLA-01", "BOLA Attempt", GroundTruthLabel.MALICIOUS, ["RULE-BOLA-01"], ["RULE-BOLA-01"], 1),
        BenchmarkEvaluator.evaluate_scenario("SCEN-BOLA-02", "BOLA Campaign", GroundTruthLabel.MALICIOUS, ["RULE-BOLA-02"], ["RULE-BOLA-02"], 1),
        BenchmarkEvaluator.evaluate_scenario("SCEN-DATA-LEAK-01", "Data Leak", GroundTruthLabel.MALICIOUS, ["RULE-DATA-LEAK-01"], ["RULE-DATA-LEAK-01"], 1),
        BenchmarkEvaluator.evaluate_scenario("SCEN-BULK-EXTRACT-01", "Bulk Extract", GroundTruthLabel.MALICIOUS, ["RULE-BULK-EXTRACT-01"], ["RULE-BULK-EXTRACT-01"], 1),
        BenchmarkEvaluator.evaluate_scenario("SCEN-EXFIL-01", "Exfil Campaign", GroundTruthLabel.MALICIOUS, ["DATA_EXFILTRATION_CAMPAIGN"], ["DATA_EXFILTRATION_CAMPAIGN"], 1),
    ]

    metrics = BenchmarkEvaluator.calculate_metrics(evals)

    assert metrics.total_scenarios == 7
    assert metrics.total_benign == 2
    assert metrics.total_malicious == 5
    assert metrics.true_positives == 5
    assert metrics.true_negatives == 2
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.accuracy == 1.0
    assert metrics.false_positive_rate == 0.0

    markdown_report = metrics.to_markdown_table()
    assert "Precision" in markdown_report
    assert "Recall" in markdown_report
    assert "F1 Score" in markdown_report
    assert "SCEN-EXFIL-01" in markdown_report
