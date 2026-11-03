"""Aegis Simulation Configuration Management.

Typed Pydantic v2 models for configuring the simulation framework with
strict local-only isolation safeguards and environment variable overrides.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class GatewayConfig(BaseModel):
    """Configuration for Aegis API Gateway communication."""

    base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for the Aegis API Gateway",
    )
    timeout_seconds: float = Field(
        default=10.0,
        ge=0.5,
        le=120.0,
        description="HTTP request timeout in seconds",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retry attempts for safe idempotent requests",
    )
    allow_synthetic_source_ip: bool = Field(
        default=False,
        description="Whether to permit synthetic X-Forwarded-For injection in local tests",
    )

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid gateway base_url: '{v}'")
        return v.rstrip("/")


class KeycloakConfig(BaseModel):
    """Configuration for Keycloak OIDC authentication service."""

    base_url: str = Field(
        default="http://localhost:8080",
        description="Base URL for the Keycloak identity provider",
    )
    realm: str = Field(
        default="aegis-dev",
        description="Target Keycloak realm name",
    )
    client_id: str = Field(
        default="aegis-local",
        description="Public OIDC client ID configured for direct access grants",
    )
    token_expiry_buffer_seconds: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Buffer in seconds before actual token expiry to trigger refresh/reacquisition",
    )

    @field_validator("base_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid keycloak base_url: '{v}'")
        return v.rstrip("/")

    @property
    def token_endpoint(self) -> str:
        """Constructs the standard OIDC token endpoint URL."""
        return f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"


class DownstreamHealthConfig(BaseModel):
    """Health check URLs for downstream microservices (used exclusively by 'doctor' command)."""

    customer_service_url: str = Field(
        default="http://localhost:8081",
        description="Internal health check URL for Customer service",
    )
    account_service_url: str = Field(
        default="http://localhost:8082",
        description="Internal health check URL for Account service",
    )
    transaction_service_url: str = Field(
        default="http://localhost:8083",
        description="Internal health check URL for Transaction service",
    )

    @field_validator("customer_service_url", "account_service_url", "transaction_service_url")
    @classmethod
    def validate_service_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid service URL: '{v}'")
        return v.rstrip("/")


class ExecutionConfig(BaseModel):
    """Runtime execution and safety isolation parameters."""

    environment_id: str = Field(
        default="local-dev",
        description="Simulation environment identifier",
    )
    allow_non_local: bool = Field(
        default=False,
        description="Explicit safeguard override: must be True to target non-local hosts",
    )
    max_concurrency: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Maximum concurrent HTTP requests during scenario execution",
    )
    default_report_format: str = Field(
        default="json",
        description="Default format for simulation reports",
    )


class SimulationConfig(BaseModel):
    """Master simulation configuration model."""

    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    keycloak: KeycloakConfig = Field(default_factory=KeycloakConfig)
    downstream_health: DownstreamHealthConfig = Field(default_factory=DownstreamHealthConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    # Dictionary of user credentials loaded securely from environment variables
    # Key: username/alias, Value: password (never serialized or logged)
    user_passwords: dict[str, str] = Field(default_factory=dict, exclude=True)

    @model_validator(mode="after")
    def enforce_local_isolation(self) -> SimulationConfig:
        """Enforces that all configured service endpoints target localhost unless explicitly allowed."""
        if self.execution.allow_non_local:
            return self

        urls_to_check = {
            "gateway.base_url": self.gateway.base_url,
            "keycloak.base_url": self.keycloak.base_url,
            "downstream.customer_service_url": self.downstream_health.customer_service_url,
            "downstream.account_service_url": self.downstream_health.account_service_url,
            "downstream.transaction_service_url": self.downstream_health.transaction_service_url,
        }

        for name, url_str in urls_to_check.items():
            parsed = urlparse(url_str)
            hostname = (parsed.hostname or "").lower()
            if hostname not in LOCAL_HOSTS:
                raise ValueError(
                    f"Safety Violation: '{name}' targets non-local host '{hostname}'. "
                    f"Simulation is restricted to localhost testbeds. "
                    f"To override, set 'execution.allow_non_local: true' with explicit authorization."
                )

        return self

    def get_password(self, username: str) -> str | None:
        """Safely retrieves a password for an identity without logging or exposing it."""
        norm_key = username.lower().replace(".", "_").replace("-", "_")
        return self.user_passwords.get(norm_key) or self.user_passwords.get(username)


def load_config(
    config_path: Path | str | None = None,
    env_file: Path | str | None = None,
) -> SimulationConfig:
    """Loads configuration from YAML file and merges environment variables.

    Loading precedence (highest to lowest):
    1. Environment variables (`SIMULATION_*`)
    2. `.env` file variables
    3. YAML configuration file
    4. Model default values
    """
    if env_file:
        load_dotenv(env_file)
    else:
        # Search for .env in current directory or simulation root
        candidates = [
            Path(".env"),
            Path("simulation/.env"),
            Path(__file__).resolve().parent.parent.parent / ".env",
        ]
        for c in candidates:
            if c.exists():
                load_dotenv(c)
                break

    # 1. Start with YAML data or defaults
    yaml_data: dict[str, Any] = {}
    resolved_path: Path | None = None

    if config_path:
        resolved_path = Path(config_path)
    else:
        default_candidates = [
            Path("config/default.yaml"),
            Path("simulation/config/default.yaml"),
            Path(__file__).resolve().parent.parent.parent / "config" / "default.yaml",
        ]
        for c in default_candidates:
            if c.exists():
                resolved_path = c
                break

    if resolved_path and resolved_path.exists():
        with open(resolved_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                yaml_data = loaded

    gateway_dict = yaml_data.get("gateway", {})
    keycloak_dict = yaml_data.get("keycloak", {})
    health_dict = yaml_data.get("downstream_health", {})
    exec_dict = yaml_data.get("execution", {})

    # 2. Apply environment variable overrides
    if env_val := os.getenv("SIMULATION_GATEWAY_BASE_URL"):
        gateway_dict["base_url"] = env_val
    if env_val := os.getenv("SIMULATION_HTTP_TIMEOUT_SECONDS"):
        gateway_dict["timeout_seconds"] = float(env_val)
    if env_val := os.getenv("SIMULATION_MAX_RETRIES"):
        gateway_dict["max_retries"] = int(env_val)
    if env_val := os.getenv("SIMULATION_ALLOW_SYNTHETIC_SOURCE_IP"):
        gateway_dict["allow_synthetic_source_ip"] = env_val.lower() in ("true", "1", "yes")

    if env_val := os.getenv("SIMULATION_KEYCLOAK_BASE_URL"):
        keycloak_dict["base_url"] = env_val
    if env_val := os.getenv("SIMULATION_KEYCLOAK_REALM"):
        keycloak_dict["realm"] = env_val
    if env_val := os.getenv("SIMULATION_KEYCLOAK_CLIENT_ID"):
        keycloak_dict["client_id"] = env_val

    if env_val := os.getenv("SIMULATION_CUSTOMER_SERVICE_URL"):
        health_dict["customer_service_url"] = env_val
    if env_val := os.getenv("SIMULATION_ACCOUNT_SERVICE_URL"):
        health_dict["account_service_url"] = env_val
    if env_val := os.getenv("SIMULATION_TRANSACTION_SERVICE_URL"):
        health_dict["transaction_service_url"] = env_val

    if env_val := os.getenv("SIMULATION_ENVIRONMENT_ID"):
        exec_dict["environment_id"] = env_val
    if env_val := os.getenv("SIMULATION_ALLOW_NON_LOCAL"):
        exec_dict["allow_non_local"] = env_val.lower() in ("true", "1", "yes")
    if env_val := os.getenv("SIMULATION_MAX_CONCURRENCY"):
        exec_dict["max_concurrency"] = int(env_val)

    # 3. Collect user passwords from SIMULATION_USER_*_PASSWORD
    passwords: dict[str, str] = {}
    prefix = "SIMULATION_USER_"
    suffix = "_PASSWORD"
    for k, v in os.environ.items():
        if k.startswith(prefix) and k.endswith(suffix) and len(k) > len(prefix) + len(suffix):
            user_part = k[len(prefix):-len(suffix)].lower()
            passwords[user_part] = v

    return SimulationConfig(
        gateway=GatewayConfig(**gateway_dict),
        keycloak=KeycloakConfig(**keycloak_dict),
        downstream_health=DownstreamHealthConfig(**health_dict),
        execution=ExecutionConfig(**exec_dict),
        user_passwords=passwords,
    )

