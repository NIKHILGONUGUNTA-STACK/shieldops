"""Comprehensive mocked unit tests for SCEN-BENIGN-01 End-to-End Customer Journey."""

from datetime import datetime, timezone
import httpx
import pytest
import respx
from typer.testing import CliRunner

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.cli import app
from simulation.clients.gateway import GatewayClient
from simulation.config import SimulationConfig
from simulation.models import ExecutionStatus
from simulation.scenarios.benign_customer_flow import BenignCustomerFlow
from simulation.scenarios.registry import get_default_registry
from simulation.scenarios.soc_verifier import SocTelemetryVerifier


@pytest.fixture
def mock_config():
    return SimulationConfig(
        gateway={"base_url": "http://localhost:8000"},
        keycloak={"base_url": "http://localhost:8080", "realm": "aegis-dev", "client_id": "aegis-local"},
        execution={"environment_id": "local-dev", "soc_verification_timeout_seconds": 1.0, "soc_verification_interval_seconds": 0.1},
        benign_flow={
            "transfer_amount": 25.0,
            "transfer_currency": "USD",
            "alex_customer_id": "10000000-0000-4000-8000-000000000001",
            "sam_customer_id": "10000000-0000-4000-8000-000000000002",
            "destination_account_reference": "ACCT-00020001",
        },
    )


def setup_mock_keycloak(respx_mock):
    """Mocks token endpoints for alex.morgan, sam.taylor, and analyst."""
    token_url = "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token"
    respx_mock.post(token_url).mock(
        side_effect=lambda request: httpx.Response(
            200,
            json={
                "access_token": (
                    "jwt-alex-token" if b"alex.morgan" in request.content
                    else "jwt-sam-token" if b"sam.taylor" in request.content
                    else "jwt-analyst-token"
                ),
                "token_type": "Bearer",
                "expires_in": 300,
            },
        )
    )


def setup_mock_gateway_endpoints(respx_mock, existing_beneficiaries=None):
    """Mocks all business API endpoints invoked during SCEN-BENIGN-01."""
    alex_id = "10000000-0000-4000-8000-000000000001"
    sam_id = "10000000-0000-4000-8000-000000000002"
    acct1_id = "20000000-0000-4000-8000-000000000001"
    sam_acct_id = "20000000-0000-4000-8000-000000000003"
    ben_id = "30000000-0000-4000-8000-000000000001"
    tx_id = "40000000-0000-4000-8000-000000000001"

    # Step A: Customer profile
    respx_mock.get(f"http://localhost:8000/api/v1/customers/{alex_id}").mock(
        return_value=httpx.Response(200, json={"id": alex_id, "customerNumber": "CUST-10001", "firstName": "Alex", "lastName": "Morgan", "status": "ACTIVE"})
    )
    respx_mock.get(f"http://localhost:8000/api/v1/customers/{alex_id}/profile").mock(
        return_value=httpx.Response(200, json={"id": alex_id, "customerNumber": "CUST-10001", "email": "alex.morgan@example.test", "status": "ACTIVE"})
    )

    # Step B: Accounts
    respx_mock.get("http://localhost:8000/api/v1/accounts").mock(
        side_effect=lambda request: httpx.Response(
            200,
            json=(
                [{"id": acct1_id, "accountNumber": "ACCT-00010001", "currency": "USD", "balance": 12500.0, "status": "ACTIVE"}]
                if "Bearer jwt-alex-token" in request.headers.get("Authorization", "")
                else [{"id": sam_acct_id, "accountNumber": "ACCT-00020001", "currency": "GBP", "balance": 5300.25, "status": "ACTIVE"}]
            ),
        )
    )
    respx_mock.get(f"http://localhost:8000/api/v1/accounts/{acct1_id}").mock(
        return_value=httpx.Response(200, json={"id": acct1_id, "accountNumber": "ACCT-00010001", "currency": "USD", "balance": 12500.0, "status": "ACTIVE"})
    )
    respx_mock.get(f"http://localhost:8000/api/v1/accounts/{acct1_id}/balance").mock(
        return_value=httpx.Response(200, json={"accountId": acct1_id, "currency": "USD", "availableBalance": 12500.0, "status": "ACTIVE"})
    )

    # Step C: Beneficiaries
    bens = existing_beneficiaries if existing_beneficiaries is not None else []
    respx_mock.get("http://localhost:8000/api/v1/beneficiaries").mock(
        return_value=httpx.Response(200, json=bens)
    )
    respx_mock.post("http://localhost:8000/api/v1/beneficiaries").mock(
        return_value=httpx.Response(201, json={"id": ben_id, "name": "Sam Taylor", "destinationAccountReference": "ACCT-00020001", "currency": "USD", "status": "PENDING"})
    )
    respx_mock.post(f"http://localhost:8000/api/v1/beneficiaries/{ben_id}/verify").mock(
        return_value=httpx.Response(200, json={"id": ben_id, "status": "VERIFIED"})
    )

    # Step D: Transfers
    respx_mock.post("http://localhost:8000/api/v1/transfers").mock(
        return_value=httpx.Response(201, json={"id": tx_id, "status": "COMPLETED", "amount": 25.0, "currency": "USD"})
    )

    # Step E: Transactions
    respx_mock.get("http://localhost:8000/api/v1/transactions").mock(
        return_value=httpx.Response(200, json=[{"id": tx_id, "status": "COMPLETED", "amount": 25.0}])
    )
    respx_mock.get(f"http://localhost:8000/api/v1/transactions/{tx_id}").mock(
        return_value=httpx.Response(200, json={"id": tx_id, "status": "COMPLETED", "amount": 25.0})
    )

    # Step F: Sam's profile & balance
    respx_mock.get(f"http://localhost:8000/api/v1/customers/{sam_id}/profile").mock(
        return_value=httpx.Response(200, json={"id": sam_id, "customerNumber": "CUST-10002", "email": "sam.taylor@example.test", "status": "ACTIVE"})
    )
    respx_mock.get(f"http://localhost:8000/api/v1/accounts/{sam_acct_id}/balance").mock(
        return_value=httpx.Response(200, json={"accountId": sam_acct_id, "currency": "GBP", "availableBalance": 5300.25, "status": "ACTIVE"})
    )


@pytest.mark.asyncio
@respx.mock
async def test_benign_flow_dry_run_success(mock_config):
    setup_mock_keycloak(respx)
    setup_mock_gateway_endpoints(respx)

    meta = get_default_registry().get_metadata("SCEN-BENIGN-01")
    flow = BenignCustomerFlow(meta, mock_config, dry_run=True)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await flow.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.total_requests >= 8
    assert summary.failed_requests == 0
    assert flow.created_resources.get("transfer_status") == "SKIPPED_DRY_RUN"
    assert "transaction_id" not in flow.created_resources

    # Assert no transfers POST call occurred during dry-run
    transfer_calls = [c for c in respx.calls if c.request.url.path == "/api/v1/transfers"]
    assert len(transfer_calls) == 0


@pytest.mark.asyncio
@respx.mock
async def test_benign_flow_live_execute_success(mock_config):
    setup_mock_keycloak(respx)
    setup_mock_gateway_endpoints(respx)

    meta = get_default_registry().get_metadata("SCEN-BENIGN-01")
    flow = BenignCustomerFlow(meta, mock_config, dry_run=False)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await flow.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    assert summary.successful_requests > 0
    assert summary.failed_requests == 0
    assert "transaction_id" in flow.created_resources
    assert flow.created_resources["transaction_status"] == "COMPLETED"

    # Verify POST to transfers occurred with Idempotency-Key
    tx_calls = [c for c in respx.calls if c.request.url.path == "/api/v1/transfers"]
    assert len(tx_calls) == 1
    assert tx_calls[0].request.headers.get("Idempotency-Key") is not None


@pytest.mark.asyncio
@respx.mock
async def test_benign_flow_reuses_existing_verified_beneficiary(mock_config):
    setup_mock_keycloak(respx)
    existing_bens = [{
        "id": "30000000-0000-4000-8000-000000000099",
        "name": "Sam Taylor",
        "destinationAccountReference": "ACCT-00020001",
        "currency": "USD",
        "status": "VERIFIED",
    }]
    setup_mock_gateway_endpoints(respx, existing_beneficiaries=existing_bens)

    meta = get_default_registry().get_metadata("SCEN-BENIGN-01")
    flow = BenignCustomerFlow(meta, mock_config, dry_run=False)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            summary = await flow.run(gateway, auth)

    assert summary.status == ExecutionStatus.SUCCESS
    # Ensure POST /api/v1/beneficiaries was never called since it was already verified
    post_ben_calls = [c for c in respx.calls if c.request.method == "POST" and c.request.url.path == "/api/v1/beneficiaries"]
    assert len(post_ben_calls) == 0
    assert flow.created_resources["beneficiary_id"] == "30000000-0000-4000-8000-000000000099"


@pytest.mark.asyncio
@respx.mock
async def test_token_separation_alex_and_sam(mock_config):
    setup_mock_keycloak(respx)
    setup_mock_gateway_endpoints(respx)

    meta = get_default_registry().get_metadata("SCEN-BENIGN-01")
    flow = BenignCustomerFlow(meta, mock_config, dry_run=True)

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            await flow.run(gateway, auth)

    alex_calls = [c for c in respx.calls if c.request.headers.get("Authorization") == "Bearer jwt-alex-token"]
    sam_calls = [c for c in respx.calls if c.request.headers.get("Authorization") == "Bearer jwt-sam-token"]

    assert len(alex_calls) > 0
    assert len(sam_calls) > 0

    # Ensure Sam never queried Alex's endpoints
    for call in sam_calls:
        assert mock_config.benign_flow.alex_customer_id not in str(call.request.url)


@pytest.mark.asyncio
@respx.mock
async def test_soc_verifier_success(mock_config):
    setup_mock_keycloak(respx)

    # Mock SOC endpoints
    respx.get("http://localhost:8000/api/v1/security/events").mock(
        return_value=httpx.Response(200, json={"totalElements": 1, "content": [{"correlationId": "cid-123"}]})
    )
    respx.get("http://localhost:8000/api/v1/security/incidents").mock(
        return_value=httpx.Response(200, json={"totalElements": 0, "content": []})
    )
    respx.get("http://localhost:8000/api/v1/security/reconciliation").mock(
        return_value=httpx.Response(200, json={"summary": {"matchedCount": 5, "coveragePercentage": 100.0}})
    )
    respx.get("http://localhost:8000/api/v1/security/posture").mock(
        return_value=httpx.Response(200, json={"content": [{"normalizedRoute": "/api/v1/customers/{customerId}", "confirmedVulnerability": False}]})
    )

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            verifier = SocTelemetryVerifier(mock_config, gateway, auth)
            result = await verifier.verify_benign_run(
                correlation_ids=["cid-123"],
                start_time=datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 11, 4, 10, 5, 0, tzinfo=timezone.utc),
                run_id="run-test-1",
            )

    assert result.verification_passed is True
    assert result.events_verified == 1
    assert result.new_incidents_count == 0
    assert result.posture_confirmed_vulnerability_false is True


@pytest.mark.asyncio
@respx.mock
async def test_soc_verifier_flags_unexpected_incident(mock_config):
    setup_mock_keycloak(respx)

    respx.get("http://localhost:8000/api/v1/security/events").mock(
        return_value=httpx.Response(200, json={"totalElements": 1, "content": [{"correlationId": "cid-456"}]})
    )
    # Incident matching Alex Morgan's customer ID
    respx.get("http://localhost:8000/api/v1/security/incidents").mock(
        return_value=httpx.Response(200, json={
            "totalElements": 1,
            "content": [{
                "id": "inc-1",
                "ruleId": "RULE-BOLA-01",
                "targetEntityValue": mock_config.benign_flow.alex_customer_id,
            }],
        })
    )
    respx.get("http://localhost:8000/api/v1/security/reconciliation").mock(
        return_value=httpx.Response(200, json={"summary": {}})
    )
    respx.get("http://localhost:8000/api/v1/security/posture").mock(
        return_value=httpx.Response(200, json={"content": []})
    )

    async with GatewayClient(mock_config.gateway) as gateway:
        async with KeycloakAuthManager(mock_config.keycloak) as auth:
            verifier = SocTelemetryVerifier(mock_config, gateway, auth)
            result = await verifier.verify_benign_run(
                correlation_ids=["cid-456"],
                start_time=datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc),
                end_time=datetime(2026, 11, 4, 10, 5, 0, tzinfo=timezone.utc),
                run_id="run-test-2",
            )

    assert result.verification_passed is False
    assert result.new_incidents_count == 1
    assert "RULE-BOLA-01" in str(result.diagnostics)


def test_cli_run_dry_run_command():
    runner = CliRunner(env={"COLUMNS": "160"})
    with respx.mock(assert_all_called=False) as respx_mock:
        setup_mock_keycloak(respx_mock)
        setup_mock_gateway_endpoints(respx_mock)

        result = runner.invoke(app, ["run", "--scenario", "SCEN-BENIGN-01", "--dry-run"])
        assert result.exit_code == 0
        assert "Aegis FinTech Simulation Runner" in result.stdout
        assert "Execution Results: SCEN-BENIGN-01" in result.stdout
        assert "SUCCESS" in result.stdout
        assert "SKIPPED_DRY_RUN" in result.stdout

