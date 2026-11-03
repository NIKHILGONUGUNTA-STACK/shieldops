"""Tests for Keycloak Authentication Manager."""

import time
import httpx
import pytest
import respx

from simulation.auth.keycloak import (
    AuthenticationError,
    KeycloakAuthManager,
    KeycloakToken,
)
from simulation.config import KeycloakConfig


@pytest.fixture
def keycloak_config():
    return KeycloakConfig(
        base_url="http://localhost:8080",
        realm="aegis-dev",
        client_id="aegis-local",
        token_expiry_buffer_seconds=30,
    )


@pytest.mark.asyncio
@respx.mock
async def test_acquire_token_success(keycloak_config):
    respx.post("http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-jwt-token-alex",
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": "mock-refresh-token",
            },
        )
    )

    auth = KeycloakAuthManager(keycloak_config)
    try:
        token = await auth.get_access_token("alex.morgan", "alex_password")
        assert token == "mock-jwt-token-alex"

        # Second call should use cache without hitting endpoint
        call_count_before = len(respx.calls)
        cached_token = await auth.get_access_token("alex.morgan")
        assert cached_token == "mock-jwt-token-alex"
        assert len(respx.calls) == call_count_before
    finally:
        await auth.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_token_expiration_and_refresh(keycloak_config):
    token_route = respx.post(
        "http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token"
    )

    # First call: initial acquisition
    token_route.side_effect = [
        httpx.Response(
            200,
            json={
                "access_token": "initial-token",
                "token_type": "Bearer",
                "expires_in": 10,  # Expires in 10s (within 30s buffer)
                "refresh_token": "refresh-123",
            },
        ),
        httpx.Response(
            200,
            json={
                "access_token": "refreshed-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": "refresh-456",
            },
        ),
    ]

    auth = KeycloakAuthManager(keycloak_config)
    try:
        t1 = await auth.get_access_token("sam.taylor", "password")
        assert t1 == "initial-token"

        # Since expires_in (10) < buffer (30), token is considered expired immediately
        # Next call should trigger refresh token flow
        t2 = await auth.get_access_token("sam.taylor")
        assert t2 == "refreshed-token"
        assert token_route.call_count == 2
    finally:
        await auth.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_invalid_credentials_error(keycloak_config):
    respx.post("http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Invalid user credentials",
            },
        )
    )

    auth = KeycloakAuthManager(keycloak_config)
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await auth.get_access_token("bad_user", "bad_pass")
        assert "Invalid user credentials" in str(exc_info.value)
    finally:
        await auth.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_client_authentication_failure(keycloak_config):
    respx.post("http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token").mock(
        return_value=httpx.Response(401, text="Unauthorized")
    )

    auth = KeycloakAuthManager(keycloak_config)
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await auth.get_access_token("alex", "pass")
        assert "client authentication failed" in str(exc_info.value).lower()
    finally:
        await auth.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_network_connection_error(keycloak_config):
    respx.post("http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    auth = KeycloakAuthManager(keycloak_config)
    try:
        with pytest.raises(AuthenticationError) as exc_info:
            await auth.get_access_token("alex", "pass")
        assert "Keycloak connection error" in str(exc_info.value)
    finally:
        await auth.aclose()


def test_token_masking():
    token = KeycloakToken(
        access_token="super-secret-jwt-token-content",
        expires_in=300,
    )
    # The secret token must never appear in repr or str
    assert "super-secret" not in repr(token)
    assert "super-secret" not in str(token)
    assert "[REDACTED]" in repr(token)


@pytest.mark.asyncio
@respx.mock
async def test_invalidate_token(keycloak_config):
    respx.post("http://localhost:8080/realms/aegis-dev/protocol/openid-connect/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "token-1", "expires_in": 300},
        )
    )

    auth = KeycloakAuthManager(keycloak_config)
    try:
        await auth.get_access_token("alex", "pass")
        assert "alex" in auth._tokens

        auth.invalidate_token("alex")
        assert "alex" not in auth._tokens
    finally:
        await auth.aclose()

