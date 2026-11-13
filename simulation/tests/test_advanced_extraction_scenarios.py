"""Tests for Phase 7.2.4.4: Advanced Bulk Extraction and Excessive Data Exposure Scenarios."""

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


def test_registry_has_all_phase_4_scenarios():
    registry = get_default_registry()
    phase4_ids = [
        "SCEN-BENIGN-PAGINATION",
        "SCEN-BENIGN-LARGE-RESP",
        "SCEN-EXTRACT-PAGINATION",
        "SCEN-DATA-RESTRICTED",
        "SCEN-EXTRACT-MULTI-RESOURCE",
        "SCEN-EXTRACT-CUMULATIVE",
        "SCEN-EDGE-NO-RESP-SIZE",
    ]
    for sc_id in phase4_ids:
        meta = registry.get_metadata(sc_id)
        assert meta is not None, f"Metadata missing for {sc_id}"
        assert meta.is_implemented is True
        cls = registry.get_class(sc_id)
        assert cls is not None, f"Class missing for {sc_id}"


@respx.mock
@pytest.mark.asyncio
async def test_benign_pagination_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/accounts?page=0&size=5").mock(
        return_value=httpx.Response(200, json=[{"id": "acc-1"}, {"id": "acc-2"}])
    )
    respx.get("http://localhost:8000/api/v1/accounts?page=1&size=5").mock(
        return_value=httpx.Response(200, json=[{"id": "acc-3"}, {"id": "acc-4"}])
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-BENIGN-PAGINATION")
    meta = registry.get_metadata("SCEN-BENIGN-PAGINATION")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


@respx.mock
@pytest.mark.asyncio
async def test_pagination_extraction_scenario(mock_config):
    setup_auth_mock(respx)
    for p in range(4):
        respx.get(f"http://localhost:8000/api/v1/accounts?page={p}&size=10").mock(
            return_value=httpx.Response(200, json=[{"id": f"acc-{p}-{i}"} for i in range(10)])
        )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXTRACT-PAGINATION")
    meta = registry.get_metadata("SCEN-EXTRACT-PAGINATION")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 4


@respx.mock
@pytest.mark.asyncio
async def test_restricted_field_retrieval_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*/profile").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "cust-alex",
                "email": "alex@example.com",
                "auth_token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
        )
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-DATA-RESTRICTED")
    meta = registry.get_metadata("SCEN-DATA-RESTRICTED")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 1


@respx.mock
@pytest.mark.asyncio
async def test_multi_resource_extraction_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(
        return_value=httpx.Response(200, json={"id": "cust-sam", "name": "Sam"})
    )
    respx.get("http://localhost:8000/api/v1/accounts").mock(
        return_value=httpx.Response(200, json=[{"id": "acc-sam", "balance": 1000.0}])
    )
    respx.get("http://localhost:8000/api/v1/transactions").mock(
        return_value=httpx.Response(200, json=[{"id": "txn-1"}])
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXTRACT-MULTI-RESOURCE")
    meta = registry.get_metadata("SCEN-EXTRACT-MULTI-RESOURCE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3


@respx.mock
@pytest.mark.asyncio
async def test_cumulative_window_extraction_scenario(mock_config):
    setup_auth_mock(respx)
    for p in range(5):
        respx.get(f"http://localhost:8000/api/v1/accounts?page={p}&size=20").mock(
            return_value=httpx.Response(200, json=[{"id": f"acc-{p}-{i}", "data": "x" * 500} for i in range(20)])
        )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXTRACT-CUMULATIVE")
    meta = registry.get_metadata("SCEN-EXTRACT-CUMULATIVE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 5


@respx.mock
@pytest.mark.asyncio
async def test_edge_no_response_size_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get(url__regex=r"http://localhost:8000/api/v1/customers/.*").mock(
        return_value=httpx.Response(200, json={"id": "cust-alex"})
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EDGE-NO-RESP-SIZE")
    meta = registry.get_metadata("SCEN-EDGE-NO-RESP-SIZE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 1


def test_comparative_evaluator_evaluates_phase_4_vectors():
    dataset = [
        (
            "SCEN-BENIGN-PAGINATION",
            "Legitimate Pagination",
            GroundTruthLabel.BENIGN,
            [
                {"status_code": 200, "url": "/api/v1/accounts?page=0&size=5", "http_method": "GET"},
                {"status_code": 200, "url": "/api/v1/accounts?page=1&size=5", "http_method": "GET"},
            ],
        ),
        (
            "SCEN-BENIGN-LARGE-RESP",
            "Authorized Statement Export",
            GroundTruthLabel.BENIGN,
            [
                {"status_code": 200, "url": "/api/v1/accounts/acc-alex/balance", "http_method": "GET", "response_size_bytes": 65000},
            ],
        ),
        (
            "SCEN-EXTRACT-PAGINATION",
            "Pagination Data Harvesting",
            GroundTruthLabel.MALICIOUS,
            [
                {"status_code": 200, "url": f"/api/v1/accounts?page={p}&size=10", "http_method": "GET"}
                for p in range(4)
            ],
        ),
        (
            "SCEN-DATA-RESTRICTED",
            "Restricted Secret Leakage",
            GroundTruthLabel.MALICIOUS,
            [
                {
                    "status_code": 200,
                    "url": "/api/v1/customers/alex/profile",
                    "http_method": "GET",
                    "observed_fields": ["id", "email", "auth_token_hash"],
                }
            ],
        ),
        (
            "SCEN-EXTRACT-MULTI-RESOURCE",
            "Multi-Domain Resource Extraction",
            GroundTruthLabel.MALICIOUS,
            [
                {"status_code": 200, "url": "/api/v1/customers/alex/profile", "http_method": "GET"},
                {"status_code": 200, "url": "/api/v1/accounts/alex-acc", "http_method": "GET"},
                {"status_code": 200, "url": "/api/v1/transactions", "http_method": "GET"},
            ],
        ),
        (
            "SCEN-EXTRACT-CUMULATIVE",
            "Cumulative Sliding Window Volume Extraction",
            GroundTruthLabel.MALICIOUS,
            [
                {"status_code": 200, "url": f"/api/v1/accounts?page={p}&size=20", "http_method": "GET"}
                for p in range(5)
            ],
        ),
    ]

    iso_evals = []
    ctx_evals = []
    for sc_id, sc_name, label, reqs in dataset:
        ev_iso, _ = ComparativeResearchEvaluator.evaluate_scenario_isolated(sc_id, sc_name, label, reqs, [1.0])
        ev_ctx, _ = ComparativeResearchEvaluator.evaluate_scenario_contextual(sc_id, sc_name, label, reqs, [1.5])
        iso_evals.append(ev_iso)
        ctx_evals.append(ev_ctx)

    iso_metrics = ComparativeResearchEvaluator.compile_mode_metrics(EvaluationMode.ISOLATED_RULES, iso_evals, [1.0])
    ctx_metrics = ComparativeResearchEvaluator.compile_mode_metrics(EvaluationMode.CONTEXTUAL_CORRELATION, ctx_evals, [1.5])

    # Contextual correlation achieves 100% recall on the new vectors
    assert ctx_metrics.recall == 1.0
    assert ctx_metrics.false_positives == 0
    assert ctx_metrics.precision == 1.0

    # Isolated rules miss pagination and multi-resource extraction because single requests look valid
    assert iso_metrics.false_negatives > 0
    assert ctx_metrics.f1_score > iso_metrics.f1_score
