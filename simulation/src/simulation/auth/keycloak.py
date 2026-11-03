"""Keycloak Authentication Manager for Aegis Simulation.

Handles token acquisition via Direct Access Grants (Password Grant),
in-memory caching with pre-expiration renewal, multi-identity support,
and strict prevention of credential or token leakage.
"""

from __future__ import annotations

import logging
import time
from typing import Any
import httpx
from pydantic import BaseModel, Field

from simulation.config import KeycloakConfig

log = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication against Keycloak fails."""
    pass


class KeycloakToken(BaseModel):
    """Typed container for OAuth2 token responses.

    Strictly masks sensitive token values in representations and logs.
    """

    access_token: str = Field(..., description="OIDC access token (JWT)")
    token_type: str = Field(default="Bearer")
    expires_in: int = Field(default=300, description="Lifetime in seconds")
    refresh_token: str | None = Field(default=None)
    refresh_expires_in: int | None = Field(default=None)
    acquired_at: float = Field(default_factory=time.time)

    def is_expired(self, buffer_seconds: int = 30) -> bool:
        """Determines if the token is expired or within the renewal buffer window."""
        elapsed = time.time() - self.acquired_at
        return elapsed >= (self.expires_in - buffer_seconds)

    def __repr__(self) -> str:
        return (
            f"KeycloakToken(token_type={self.token_type!r}, "
            f"expires_in={self.expires_in}, "
            f"access_token='***[REDACTED]***')"
        )

    def __str__(self) -> str:
        return self.__repr__()


class KeycloakAuthManager:
    """Manages Keycloak authentication and token lifecycle for simulation identities."""

    def __init__(
        self,
        config: KeycloakConfig,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._custom_client = http_client is not None
        self._client = http_client or httpx.AsyncClient(timeout=10.0)
        self._tokens: dict[str, KeycloakToken] = {}

    async def get_access_token(
        self,
        identity: str,
        password: str | None = None,
    ) -> str:
        """Retrieves a valid Bearer access token for the specified identity.

        Uses in-memory cache if token is still valid. If expired or missing,
        acquires a new token using password or refresh grant.
        """
        if not identity or not identity.strip():
            raise AuthenticationError("Identity cannot be empty")

        clean_identity = identity.strip()

        # 1. Check in-memory cache
        cached = self._tokens.get(clean_identity)
        if cached and not cached.is_expired(self.config.token_expiry_buffer_seconds):
            return cached.access_token

        # 2. Try refresh if cached and has valid refresh token
        if cached and cached.refresh_token:
            try:
                token = await self._refresh_token(cached.refresh_token)
                self._tokens[clean_identity] = token
                log.debug("Successfully refreshed token for identity '%s'", clean_identity)
                return token.access_token
            except Exception as e:
                log.debug("Refresh token renewal failed for '%s': %s. Re-authenticating.", clean_identity, e)

        # 3. Direct Access Grant (Password)
        if not password:
            raise AuthenticationError(
                f"Password required to authenticate identity '{clean_identity}' (no valid cached token)"
            )

        token = await self._acquire_password_token(clean_identity, password)
        self._tokens[clean_identity] = token
        log.debug("Acquired new access token for identity '%s'", clean_identity)
        return token.access_token

    async def _acquire_password_token(self, username: str, password: str) -> KeycloakToken:
        """Executes Resource Owner Password Credentials Grant."""
        data = {
            "grant_type": "password",
            "client_id": self.config.client_id,
            "username": username,
            "password": password,
        }

        try:
            response = await self._client.post(
                self.config.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.RequestError as e:
            raise AuthenticationError(
                f"Keycloak connection error during token acquisition for '{username}': {e}"
            ) from e

        if response.status_code == 200:
            try:
                payload = response.json()
                return KeycloakToken(
                    access_token=payload["access_token"],
                    token_type=payload.get("token_type", "Bearer"),
                    expires_in=int(payload.get("expires_in", 300)),
                    refresh_token=payload.get("refresh_token"),
                    refresh_expires_in=payload.get("refresh_expires_in"),
                    acquired_at=time.time(),
                )
            except (KeyError, ValueError) as e:
                raise AuthenticationError(f"Malformed Keycloak token response for '{username}': {e}") from e

        if response.status_code == 400:
            error_data = response.json() if "application/json" in response.headers.get("content-type", "") else {}
            error_desc = error_data.get("error_description") or error_data.get("error") or response.text
            raise AuthenticationError(
                f"Authentication failed for '{username}': {error_desc} (HTTP 400)"
            )

        if response.status_code == 401:
            raise AuthenticationError(
                f"Keycloak client authentication failed for client '{self.config.client_id}' (HTTP 401)"
            )

        raise AuthenticationError(
            f"Unexpected Keycloak response (HTTP {response.status_code}): {response.text}"
        )

    async def _refresh_token(self, refresh_token: str) -> KeycloakToken:
        """Refreshes an existing token using refresh_token grant."""
        data = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": refresh_token,
        }

        response = await self._client.post(
            self.config.token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            raise AuthenticationError(f"Token refresh rejected (HTTP {response.status_code})")

        payload = response.json()
        return KeycloakToken(
            access_token=payload["access_token"],
            token_type=payload.get("token_type", "Bearer"),
            expires_in=int(payload.get("expires_in", 300)),
            refresh_token=payload.get("refresh_token", refresh_token),
            refresh_expires_in=payload.get("refresh_expires_in"),
            acquired_at=time.time(),
        )

    def invalidate_token(self, identity: str) -> None:
        """Removes the cached token for an identity."""
        self._tokens.pop(identity.strip(), None)

    def clear_cache(self) -> None:
        """Flushes all cached identity tokens."""
        self._tokens.clear()

    async def aclose(self) -> None:
        """Closes the underlying HTTP client if internally managed."""
        if not self._custom_client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> KeycloakAuthManager:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

