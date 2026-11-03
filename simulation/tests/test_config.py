"""Tests for simulation configuration and isolation safeguards."""

import os
from pathlib import Path
import pytest
from pydantic import ValidationError

from simulation.config import (
    GatewayConfig,
    KeycloakConfig,
    SimulationConfig,
    load_config,
)


def test_default_config():
    config = SimulationConfig()
    assert config.gateway.base_url == "http://localhost:8000"
    assert config.gateway.timeout_seconds == 10.0
    assert config.gateway.max_retries == 2
    assert config.gateway.allow_synthetic_source_ip is False

    assert config.keycloak.base_url == "http://localhost:8080"
    assert config.keycloak.realm == "aegis-dev"
    assert config.keycloak.client_id == "aegis-local"
    assert config.keycloak.token_endpoint == (
        "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token"
    )

    assert config.execution.environment_id == "local-dev"
    assert config.execution.allow_non_local is False


def test_reject_non_local_gateway_by_default():
    with pytest.raises(ValidationError) as exc_info:
        SimulationConfig(
            gateway=GatewayConfig(base_url="https://api.external-cloud.com")
        )
    assert "Safety Violation" in str(exc_info.value)
    assert "api.external-cloud.com" in str(exc_info.value)


def test_reject_non_local_keycloak_by_default():
    with pytest.raises(ValidationError) as exc_info:
        SimulationConfig(
            keycloak=KeycloakConfig(base_url="https://auth.company.corp")
        )
    assert "Safety Violation" in str(exc_info.value)
    assert "auth.company.corp" in str(exc_info.value)


def test_allow_non_local_when_explicitly_configured():
    config = SimulationConfig(
        gateway=GatewayConfig(base_url="https://api.external-cloud.com"),
        execution={"allow_non_local": True},  # type: ignore
    )
    assert config.gateway.base_url == "https://api.external-cloud.com"
    assert config.execution.allow_non_local is True


def test_invalid_url_format():
    with pytest.raises(ValidationError):
        GatewayConfig(base_url="not-a-valid-url")


def test_env_var_overrides(monkeypatch):
    monkeypatch.setenv("SIMULATION_GATEWAY_BASE_URL", "http://127.0.0.1:9000")
    monkeypatch.setenv("SIMULATION_HTTP_TIMEOUT_SECONDS", "25.5")
    monkeypatch.setenv("SIMULATION_MAX_RETRIES", "4")
    monkeypatch.setenv("SIMULATION_ALLOW_SYNTHETIC_SOURCE_IP", "true")
    monkeypatch.setenv("SIMULATION_KEYCLOAK_REALM", "custom-realm")
    monkeypatch.setenv("SIMULATION_USER_ALEX_PASSWORD", "secret123")

    config = load_config(config_path=None)

    assert config.gateway.base_url == "http://127.0.0.1:9000"
    assert config.gateway.timeout_seconds == 25.5
    assert config.gateway.max_retries == 4
    assert config.gateway.allow_synthetic_source_ip is True
    assert config.keycloak.realm == "custom-realm"

    # Password extraction
    assert config.get_password("alex") == "secret123"
    # Passwords should be excluded from standard model dump
    dump = config.model_dump()
    assert "user_passwords" not in dump


def test_yaml_config_loading(tmp_path: Path):
    yaml_file = tmp_path / "custom.yaml"
    yaml_file.write_text(
        """
gateway:
  base_url: "http://localhost:8888"
  timeout_seconds: 5.0
keycloak:
  base_url: "http://127.0.0.1:8080"
  realm: "test-realm"
execution:
  environment_id: "test-env"
  max_concurrency: 10
""",
        encoding="utf-8",
    )

    config = load_config(config_path=yaml_file)
    assert config.gateway.base_url == "http://localhost:8888"
    assert config.gateway.timeout_seconds == 5.0
    assert config.keycloak.realm == "test-realm"
    assert config.execution.environment_id == "test-env"
    assert config.execution.max_concurrency == 10

