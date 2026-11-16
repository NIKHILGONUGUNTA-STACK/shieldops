"""Tests for Phase 7.3.1 Full-Scale Security Simulation and Campaign Orchestration Engine."""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import httpx
import pytest
import respx

from simulation.auth.keycloak import KeycloakAuthManager
from simulation.config import SimulationConfig
from simulation.models import ExecutionStatus
from simulation.scenarios.registry import get_default_registry
from simulation.orchestration.templates import (
    CampaignRunConfig,
    TrafficMix,
    get_default_campaign_templates,
)
from simulation.orchestration.orchestrator import CampaignOrchestrator


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


def setup_respx_gateway_mocks(respx_mock):
    """Mocks standard gateway and Keycloak endpoints for safe simulation testing."""
    # Keycloak auth
    token_url = "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token"
    respx_mock.post(token_url).mock(
        return_value=httpx.Response(200, json={"access_token": "mock-jwt-token", "expires_in": 300})
    )

    # Customer endpoints
    respx_mock.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001/profile").mock(
        return_value=httpx.Response(200, json={"id": "10000000-0000-4000-8000-000000000001", "name": "Alex Morgan"})
    )
    respx_mock.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000002").mock(
        return_value=httpx.Response(200, json={"id": "10000000-0000-4000-8000-000000000002", "name": "Sam Taylor"})
    )
    respx_mock.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000002/profile").mock(
        return_value=httpx.Response(403, json={"error": "Forbidden: access denied"})
    )
    respx_mock.get("http://localhost:8000/api/v1/customers/10000000-0000-4000-8000-000000000001").mock(
        return_value=httpx.Response(200, json={"id": "10000000-0000-4000-8000-000000000001", "name": "Alex Morgan"})
    )
    respx_mock.get("http://localhost:8000/api/v1/customers").mock(
        return_value=httpx.Response(200, json=[{"id": "c1"}])
    )

    # Account endpoints
    respx_mock.get("http://localhost:8000/api/v1/accounts/ACCT-ALEX-01/balance").mock(
        return_value=httpx.Response(200, json={"accountId": "ACCT-ALEX-01", "balance": 12358.74})
    )
    respx_mock.get("http://localhost:8000/api/v1/accounts").mock(
        return_value=httpx.Response(200, json=[{
            "id": "ACCT-ALEX-01",
            "accountNumber": "ACCT-ALEX-01",
            "customerId": "10000000-0000-4000-8000-000000000001",
            "status": "ACTIVE",
            "currency": "USD",
            "balance": 12358.74
        }, {
            "id": "ACCT-SAM-01",
            "accountNumber": "ACCT-SAM-01",
            "customerId": "10000000-0000-4000-8000-000000000002",
            "status": "ACTIVE",
            "currency": "GBP",
            "balance": 5300.25
        }])
    )

    # Transfer endpoints
    respx_mock.post("http://localhost:8000/api/v1/transfers").mock(
        return_value=httpx.Response(201, json={"id": "tx-1234", "status": "COMPLETED", "amount": 25.0, "currency": "USD"})
    )
    respx_mock.get("http://localhost:8000/api/v1/transfers").mock(
        return_value=httpx.Response(200, json={"content": [], "totalElements": 0})
    )
    respx_mock.get("http://localhost:8000/api/v1/transfers/history").mock(
        return_value=httpx.Response(200, json={"content": [], "totalElements": 0})
    )

    # Actuator & Infra
    respx_mock.get("http://localhost:8000/actuator/health/readiness").mock(
        return_value=httpx.Response(200, json={"status": "UP"})
    )
    respx_mock.get("http://localhost:8000/api/v1/nonexistent/service/boundary").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    respx_mock.get("http://localhost:8000/actuator/env").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    respx_mock.get("http://localhost:8000/swagger-ui.html").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )


def test_registry_has_all_43_scenarios():
    """Validates that registry contains all 43 implemented scenarios."""
    registry = get_default_registry()
    scenarios = registry.list_all()
    assert len(scenarios) >= 43

    new_scenarios = [
        "SCEN-BENIGN-BENEFICIARY",
        "SCEN-SEC-AUTH-ABUSE",
        "SCEN-SEC-INJECTION-PROBE",
        "SCEN-MIXED-CONCURRENT",
        "SCEN-MIXED-MULTI-TENANT",
        "SCEN-INFRA-BACKLOG",
        "SCEN-INFRA-UNAVAILABLE",
    ]
    for sc_id in new_scenarios:
        meta = registry.get_metadata(sc_id)
        assert meta is not None, f"Scenario {sc_id} missing in registry"
        assert meta.is_implemented is True, f"Scenario {sc_id} marked not implemented"
        assert registry.get_class(sc_id) is not None, f"Class {sc_id} missing"


def test_campaign_templates_catalogue():
    """Validates the standard 5 campaign templates."""
    templates = get_default_campaign_templates()
    assert len(templates) == 5

    assert "TPL-BENIGN-WORKDAY" in templates
    assert "TPL-BOLA-EXFIL-CAMPAIGN" in templates
    assert "TPL-LOW-SLOW-STEALTH" in templates
    assert "TPL-FULL-MIXED-WORKLOAD" in templates
    assert "TPL-INFRA-RESILIENCE" in templates

    tpl = templates["TPL-BOLA-EXFIL-CAMPAIGN"]
    assert len(tpl.stages) == 3
    assert tpl.category == "SECURITY"


@pytest.mark.asyncio
async def test_orchestrator_sequential_benign_run(mock_config, respx_mock):
    """Executes benign workday campaign template in dry run mode."""
    setup_respx_gateway_mocks(respx_mock)
    orchestrator = CampaignOrchestrator(mock_config)

    config = CampaignRunConfig(
        template_id="TPL-BENIGN-WORKDAY",
        duration_seconds=10,
        request_rate_per_sec=10.0,
        concurrency=1,
        dry_run=True,
    )

    summary = await orchestrator.run_campaign(config)

    assert summary is not None
    assert summary.run_id.startswith("SIM-RUN-")
    assert summary.total_stages > 0
    assert orchestrator.total_requests > 0
    assert orchestrator.status == ExecutionStatus.SUCCESS
    assert summary.overall_passed is True


def test_orchestrator_pause_resume_stop(mock_config):
    """Tests orchestrator pause, resume, and hard stop controls."""
    orchestrator = CampaignOrchestrator(mock_config)

    # Test state transitions
    orchestrator.status = ExecutionStatus.RUNNING
    orchestrator.pause()
    assert orchestrator.status == ExecutionStatus.PAUSED
    assert not orchestrator._pause_event.is_set()

    orchestrator.resume()
    assert orchestrator.status == ExecutionStatus.RUNNING
    assert orchestrator._pause_event.is_set()

    orchestrator.stop()
    assert orchestrator.status == ExecutionStatus.STOPPED
    assert orchestrator._stop_requested is True


@pytest.mark.asyncio
async def test_orchestrator_bola_campaign_assertions(mock_config, respx_mock):
    """Executes BOLA multi-stage campaign and verifies expected rule assertions."""
    setup_respx_gateway_mocks(respx_mock)
    orchestrator = CampaignOrchestrator(mock_config)

    config = CampaignRunConfig(
        template_id="TPL-BOLA-EXFIL-CAMPAIGN",
        duration_seconds=10,
        request_rate_per_sec=10.0,
        concurrency=1,
        dry_run=True,
    )

    summary = await orchestrator.run_campaign(config)

    assert summary is not None
    assert orchestrator.total_requests > 0
    assert summary.campaign_id == "TPL-BOLA-EXFIL-CAMPAIGN"
    assert len(summary.stage_reports) > 0


@pytest.mark.asyncio
async def test_orchestrator_mixed_concurrent(mock_config, respx_mock):
    """Executes mixed workload template with concurrency."""
    setup_respx_gateway_mocks(respx_mock)
    orchestrator = CampaignOrchestrator(mock_config)

    config = CampaignRunConfig(
        template_id="TPL-FULL-MIXED-WORKLOAD",
        duration_seconds=2,  # Short duration
        request_rate_per_sec=20.0,
        concurrency=2,
        traffic_mix=TrafficMix.MIXED,
        dry_run=True,
    )

    summary = await orchestrator.run_campaign(config)

    assert summary is not None
    assert orchestrator.total_requests >= 0
    assert orchestrator.status == ExecutionStatus.SUCCESS


def test_report_persistence(tmp_path, mock_config):
    """Verifies that campaign reports are saved separately from security findings."""
    orchestrator = CampaignOrchestrator(mock_config)
    orchestrator.active_run_id = "SIM-RUN-TEST-001"
    orchestrator.status = ExecutionStatus.SUCCESS
    orchestrator.started_at = datetime.now(timezone.utc)
    orchestrator.finished_at = datetime.now(timezone.utc)
    orchestrator.total_requests = 42
    orchestrator.successful_requests = 40
    orchestrator.failed_requests = 2

    summary = orchestrator._build_verification_summary()
    orchestrator._persist_report(summary)

    report_path = Path("simulation/reports/campaigns/SIM-RUN-TEST-001.json")
    assert report_path.exists()

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["run_id"] == "SIM-RUN-TEST-001"
    assert data["total_requests"] == 42
    assert data["successful_requests"] == 40
    assert data["status"] == "SUCCESS"

    # Clean up test file
    report_path.unlink(missing_ok=True)
