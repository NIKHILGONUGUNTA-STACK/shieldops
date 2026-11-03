"""Tests for the simulation CLI commands."""

import httpx
import pytest
import respx
from typer.testing import CliRunner

from simulation.cli import app

runner = CliRunner(env={"COLUMNS": "160"})


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "Aegis Simulation Framework" in result.stdout
    assert "v0.1.0" in result.stdout


def test_cli_config_validate():
    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    assert "Aegis Simulation Configuration" in result.stdout
    assert "Configuration is valid" in result.stdout


def test_cli_config_validate_with_invalid_file(tmp_path):
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("gateway:\n  base_url: 'not-a-valid-url'\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", "--config", str(bad_config)])
    assert result.exit_code == 1
    assert "Configuration Validation Error" in result.stdout


def test_cli_scenarios_list():
    result = runner.invoke(app, ["scenarios", "list"])
    assert result.exit_code == 0
    assert "SCEN-BENIGN-01" in result.stdout
    assert "SCEN-BOLA-01" in result.stdout
    assert "SCEN-INJ-01" in result.stdout
    assert "Planned (Phase 7.2.3)" in result.stdout


@respx.mock
def test_cli_doctor_all_healthy():
    respx.get("http://localhost:8000/actuator/health/readiness").mock(
        return_value=httpx.Response(200, json={"status": "UP"})
    )
    respx.get("http://localhost:8080/realms/aegis-dev/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200, json={"issuer": "http://localhost:8080/realms/aegis-dev"})
    )
    respx.get("http://localhost:8081/actuator/health/readiness").mock(
        return_value=httpx.Response(200, json={"status": "UP"})
    )
    respx.get("http://localhost:8082/actuator/health/readiness").mock(
        return_value=httpx.Response(200, json={"status": "UP"})
    )
    respx.get("http://localhost:8083/actuator/health/readiness").mock(
        return_value=httpx.Response(200, json={"status": "UP"})
    )

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Aegis Testbed Diagnostic Health Matrix" in result.stdout
    assert "All Aegis FinTech testbed services are reachable and healthy" in result.stdout


@respx.mock
def test_cli_doctor_unreachable_service():
    respx.get("http://localhost:8000/actuator/health/readiness").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )
    respx.get("http://localhost:8080/realms/aegis-dev/.well-known/openid-configuration").mock(
        return_value=httpx.Response(200)
    )
    respx.get("http://localhost:8081/actuator/health/readiness").mock(
        return_value=httpx.Response(200)
    )
    respx.get("http://localhost:8082/actuator/health/readiness").mock(
        return_value=httpx.Response(200)
    )
    respx.get("http://localhost:8083/actuator/health/readiness").mock(
        return_value=httpx.Response(200)
    )

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "DOWN" in result.stdout
    assert "Some testbed services are unreachable" in result.stdout
