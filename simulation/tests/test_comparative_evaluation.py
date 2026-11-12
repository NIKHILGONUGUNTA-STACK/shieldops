"""Tests for Comparative Research Evaluation and Adversarial Robustness."""

import httpx
import pytest
import respx

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import ExecutionStatus
from simulation.reporting.comparative_evaluator import (
    ComparativeResearchEvaluator,
    EvaluationMode,
)
from simulation.reporting.evaluation import GroundTruthLabel
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
        return_value=httpx.Response(200, json={"access_token": "mock-jwt-token", "expires_in": 300})
    )


@respx.mock
@pytest.mark.asyncio
async def test_benign_multi_resource_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(return_value=httpx.Response(200, json={}))
    respx.get("http://localhost:8000/api/v1/accounts").mock(return_value=httpx.Response(200, json=[]))
    respx.get("http://localhost:8000/api/v1/transactions").mock(return_value=httpx.Response(200, json=[]))

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-BENIGN-03")
    meta = registry.get_metadata("SCEN-BENIGN-03")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 4
    assert summary.failed_requests == 0


@respx.mock
@pytest.mark.asyncio
async def test_benign_shared_ip_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(return_value=httpx.Response(200, json={}))

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-BENIGN-05")
    meta = registry.get_metadata("SCEN-BENIGN-05")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


@respx.mock
@pytest.mark.asyncio
async def test_bola_repeated_attempts_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(return_value=httpx.Response(403))

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-BOLA-03")
    meta = registry.get_metadata("SCEN-BOLA-03")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3
    assert summary.status_distribution.get(403) == 3


@respx.mock
@pytest.mark.asyncio
async def test_edge_duplicate_events_scenario_execution(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/accounts").mock(return_value=httpx.Response(200, json=[]))

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EDGE-DUPLICATE")
    meta = registry.get_metadata("SCEN-EDGE-DUPLICATE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


def test_comparative_evaluation_shows_contextual_superiority():
    dataset = [
        # Benign scenarios
        ("SCEN-BENIGN-01", "Normal Customer Journey", GroundTruthLabel.BENIGN, [{"status_code": 200, "url": "/api/v1/customers/1000", "http_method": "GET"}]),
        ("SCEN-BENIGN-02", "Repeated Own Reads", GroundTruthLabel.BENIGN, [{"status_code": 200, "url": "/api/v1/customers/1000", "http_method": "GET"}] * 5),
        ("SCEN-BENIGN-03", "Multi-Resource Reads", GroundTruthLabel.BENIGN, [
            {"status_code": 200, "url": "/api/v1/customers/1000", "http_method": "GET"},
            {"status_code": 200, "url": "/api/v1/accounts", "http_method": "GET"},
        ]),
        ("SCEN-BENIGN-06", "Legitimate Denied Admin Action", GroundTruthLabel.BENIGN, [
            {"status_code": 403, "url": "/api/v1/security/overview", "http_method": "GET"}
        ]),
        # Malicious scenarios
        ("SCEN-BOLA-01", "Single Cross-Owner Access", GroundTruthLabel.MALICIOUS, [
            {"status_code": 403, "url": "/api/v1/customers/2000", "http_method": "GET"}
        ]),
        ("SCEN-BOLA-02", "BOLA Probe Campaign", GroundTruthLabel.MALICIOUS, [
            {"status_code": 403, "url": "/api/v1/accounts/acc-victim-1", "http_method": "GET"},
            {"status_code": 403, "url": "/api/v1/accounts/acc-victim-2", "http_method": "GET"},
        ]),
        ("SCEN-BULK-EXTRACT-01", "Bulk Harvest", GroundTruthLabel.MALICIOUS, [
            {"status_code": 200, "url": "/api/v1/customers/cust-harv-1", "http_method": "GET"},
            {"status_code": 200, "url": "/api/v1/customers/cust-harv-2", "http_method": "GET"},
            {"status_code": 200, "url": "/api/v1/customers/cust-harv-3", "http_method": "GET"},
        ]),
        ("SCEN-EXFIL-01", "Multi-Stage Exfiltration", GroundTruthLabel.MALICIOUS, [
            {"status_code": 404, "url": "/actuator/env", "http_method": "GET"},
            {"status_code": 403, "url": "/api/v1/accounts/acc-probe-1", "http_method": "GET"},
            {"status_code": 200, "url": "/api/v1/customers/2000", "http_method": "GET"},
        ]),
    ]

    iso_evals = []
    iso_latencies = []
    for sc_id, sc_name, label, reqs in dataset:
        ev, lat = ComparativeResearchEvaluator.evaluate_scenario_isolated(sc_id, sc_name, label, reqs, [1.2, 1.5])
        iso_evals.append(ev)
        iso_latencies.append(lat)

    ctx_evals = []
    ctx_latencies = []
    for sc_id, sc_name, label, reqs in dataset:
        ev, lat = ComparativeResearchEvaluator.evaluate_scenario_contextual(sc_id, sc_name, label, reqs, [1.4, 1.8])
        ctx_evals.append(ev)
        ctx_latencies.append(lat)

    iso_metrics = ComparativeResearchEvaluator.compile_mode_metrics(EvaluationMode.ISOLATED_RULES, iso_evals, iso_latencies)
    ctx_metrics = ComparativeResearchEvaluator.compile_mode_metrics(EvaluationMode.CONTEXTUAL_CORRELATION, ctx_evals, ctx_latencies)

    # Assert that Contextual Correlation achieves:
    # 1. Zero False Positives (whereas isolated rules had false positive on SCEN-BENIGN-06)
    assert ctx_metrics.false_positives == 0
    assert ctx_metrics.precision == 1.0
    assert ctx_metrics.recall == 1.0
    assert ctx_metrics.f1_score == 1.0
    assert ctx_metrics.false_positive_rate == 0.0

    # 2. Contextual F1 score is strictly greater than or equal to isolated rules F1
    assert ctx_metrics.f1_score >= iso_metrics.f1_score


def test_robustness_findings_evaluation():
    findings = ComparativeResearchEvaluator.evaluate_robustness()
    assert len(findings) >= 6
    assert all(f.passed for f in findings)
    assert any("Sliding-Window" in f.test_case for f in findings)
    assert any("Duplicate" in f.test_case for f in findings)
    assert any("Shared-IP" in f.test_case for f in findings)
