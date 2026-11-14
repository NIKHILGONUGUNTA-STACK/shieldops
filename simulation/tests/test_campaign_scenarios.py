"""Tests for Phase 7.2.4.5: Multi-Stage Exfiltration Campaign Simulation Scenarios."""

import httpx
import pytest
import respx

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import ExecutionStatus
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


def test_registry_has_all_campaign_scenarios():
    registry = get_default_registry()
    campaign_ids = [
        "SCEN-EXFIL-RECON-PROBE",
        "SCEN-EXFIL-PROBE-EXTRACT",
        "SCEN-EXFIL-EXPOSE-BULK",
        "SCEN-EXFIL-LOW-SLOW-MULTI",
        "SCEN-BENIGN-LOOKALIKE",
        "SCEN-MULTI-01",
    ]
    for sc_id in campaign_ids:
        meta = registry.get_metadata(sc_id)
        assert meta is not None, f"Metadata missing for {sc_id}"
        assert meta.is_implemented is True
        cls = registry.get_class(sc_id)
        assert cls is not None, f"Class missing for {sc_id}"


@respx.mock
@pytest.mark.asyncio
async def test_recon_then_probe_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/actuator/env").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001").mock(
        return_value=httpx.Response(403, json={"error": "Forbidden"})
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXFIL-RECON-PROBE")
    meta = registry.get_metadata("SCEN-EXFIL-RECON-PROBE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


@respx.mock
@pytest.mark.asyncio
async def test_probe_then_extract_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001").mock(
        return_value=httpx.Response(403, json={"error": "Forbidden"})
    )
    respx.get("http://localhost:8000/api/v1/accounts/30000000-0000-4000-8000-000000000003").mock(
        return_value=httpx.Response(200, json={"id": "30000000-0000-4000-8000-000000000003", "balance": 9999.0})
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXFIL-PROBE-EXTRACT")
    meta = registry.get_metadata("SCEN-EXFIL-PROBE-EXTRACT")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


@respx.mock
@pytest.mark.asyncio
async def test_expose_then_bulk_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000002/profile").mock(
        return_value=httpx.Response(200, json={"id": "sam-id", "email": "sam@example.com", "auth_token_hash": "hash"})
    )
    for p in range(3):
        respx.get(f"http://localhost:8000/api/v1/accounts?page={p}&size=10").mock(
            return_value=httpx.Response(200, json=[{"id": f"acc-{p}"}])
        )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXFIL-EXPOSE-BULK")
    meta = registry.get_metadata("SCEN-EXFIL-EXPOSE-BULK")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 4


@respx.mock
@pytest.mark.asyncio
async def test_low_slow_multi_domain_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000002").mock(
        return_value=httpx.Response(200, json={"id": "sam-id"})
    )
    respx.get("http://localhost:8000/api/v1/accounts").mock(
        return_value=httpx.Response(200, json=[{"id": "acc-1"}])
    )
    respx.get("http://localhost:8000/api/v1/transactions").mock(
        return_value=httpx.Response(200, json=[{"id": "tx-1"}])
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-EXFIL-LOW-SLOW-MULTI")
    meta = registry.get_metadata("SCEN-EXFIL-LOW-SLOW-MULTI")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3


@respx.mock
@pytest.mark.asyncio
async def test_benign_lookalike_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/favicon.ico").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001/profile").mock(
        return_value=httpx.Response(200, json={"id": "alex-id", "name": "Alex Morgan"})
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-BENIGN-LOOKALIKE")
    meta = registry.get_metadata("SCEN-BENIGN-LOOKALIKE")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 2


@respx.mock
@pytest.mark.asyncio
async def test_multivector_campaign_scenario(mock_config):
    setup_auth_mock(respx)
    respx.get("http://localhost:8000/actuator/mappings").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001").mock(
        return_value=httpx.Response(403, json={"error": "Forbidden"})
    )
    respx.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000002/profile").mock(
        return_value=httpx.Response(200, json={"id": "sam-id", "email": "sam@example.com"})
    )

    registry = get_default_registry()
    scenario_cls = registry.get_class("SCEN-MULTI-01")
    meta = registry.get_metadata("SCEN-MULTI-01")
    scenario = scenario_cls(meta, mock_config)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await scenario.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests == 3

