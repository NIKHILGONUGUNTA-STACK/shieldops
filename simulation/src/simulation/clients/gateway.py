"""Aegis API Gateway Asynchronous HTTP Client.

Provides structured, safe HTTP communication with the Aegis Gateway,
enforcing unique correlation IDs, latency measurement, strict retry bounds
limited to safe idempotent operations (never auto-retrying non-idempotent POSTs),
and controlled synthetic source-IP injection only when explicitly permitted.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any
import httpx
from pydantic import BaseModel, Field

from simulation.config import GatewayConfig

log = logging.getLogger(__name__)

SAFE_IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS"}
RETRYABLE_STATUS_CODES = {502, 503, 504}


class GatewayClientError(Exception):
    """Base exception for Gateway client communication errors."""
    pass


class GatewayTimeoutError(GatewayClientError):
    """Raised when an HTTP request to the Gateway times out."""
    pass


class GatewayConnectionError(GatewayClientError):
    """Raised when a network connection failure occurs while contacting the Gateway."""
    pass


class GatewayResponse(BaseModel):
    """Structured response container capturing metadata and timing for simulation analysis."""

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    correlation_id: str
    duration_ms: float
    content: bytes = Field(exclude=True)
    text: str = Field(exclude=True)
    http_method: str
    url: str

    def json(self) -> Any:
        """Parses the response body as JSON."""
        import json as json_lib
        return json_lib.loads(self.text)

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600


class GatewayClient:
    """Asynchronous client for interacting with the Aegis Gateway."""

    def __init__(
        self,
        config: GatewayConfig,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._custom_client = http_client is not None
        self._client = http_client or httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout_seconds,
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        json: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        """Executes an HTTP request against the Gateway with structured instrumentation.

        Strict Safety Invariant:
        - Safe methods (GET, HEAD, OPTIONS) are eligible for bounded retries on transient errors.
        - Non-idempotent operations (POST, PUT, DELETE, PATCH) are NEVER automatically retried
          without an explicit idempotency strategy.
        """
        http_method = method.upper().strip()
        req_headers = dict(headers or {})

        # 1. Inject or preserve Correlation ID
        cid = correlation_id or req_headers.get("X-Correlation-Id") or str(uuid.uuid4())
        req_headers["X-Correlation-Id"] = cid

        # 2. Inject Bearer token if provided
        if token and not req_headers.get("Authorization"):
            req_headers["Authorization"] = f"Bearer {token}"

        # 3. Controlled Synthetic Source IP Handling
        if source_ip:
            if not self.config.allow_synthetic_source_ip:
                raise GatewayClientError(
                    f"Cannot inject synthetic source IP '{source_ip}': "
                    f"synthetic source IP injection is disabled in Gateway configuration."
                )
            req_headers["X-Forwarded-For"] = source_ip

        # 4. Determine retry policy
        is_safe_method = http_method in SAFE_IDEMPOTENT_METHODS
        max_attempts = (self.config.max_retries + 1) if is_safe_method else 1

        target_path = path if path.startswith("/") else f"/{path}"
        target_url = f"{self.config.base_url.rstrip('/')}{target_path}"

        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            start_time = time.perf_counter()
            try:
                raw_response = await self._client.request(
                    method=http_method,
                    url=target_path,
                    json=json,
                    data=data,
                    headers=req_headers,
                    params=params,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                # Check if safe method hit a transient retryable 5xx code
                if is_safe_method and raw_response.status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts:
                    log.warning(
                        "Transient HTTP %d received for %s %s (attempt %d/%d). Retrying...",
                        raw_response.status_code, http_method, target_path, attempt, max_attempts,
                    )
                    await raw_response.aclose()
                    continue

                return GatewayResponse(
                    status_code=raw_response.status_code,
                    headers=dict(raw_response.headers),
                    correlation_id=cid,
                    duration_ms=round(duration_ms, 2),
                    content=raw_response.content,
                    text=raw_response.text,
                    http_method=http_method,
                    url=target_url,
                )

            except httpx.TimeoutException as e:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                last_error = GatewayTimeoutError(
                    f"Request {http_method} {target_path} timed out after {self.config.timeout_seconds}s "
                    f"[CID: {cid}]"
                )
                if is_safe_method and attempt < max_attempts:
                    log.warning(
                        "Timeout on %s %s (attempt %d/%d). Retrying...",
                        http_method, target_path, attempt, max_attempts,
                    )
                    continue
                raise last_error from e

            except httpx.RequestError as e:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                last_error = GatewayConnectionError(
                    f"Connection failed for {http_method} {target_path}: {e} [CID: {cid}]"
                )
                if is_safe_method and attempt < max_attempts:
                    log.warning(
                        "Network error on %s %s (attempt %d/%d): %s. Retrying...",
                        http_method, target_path, attempt, max_attempts, e,
                    )
                    continue
                raise last_error from e

        if last_error:
            raise last_error

        raise GatewayClientError(f"Request {http_method} {target_path} failed after {max_attempts} attempts")

    async def get(
        self,
        path: str,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        """Convenience method for GET requests."""
        return await self.request(
            "GET",
            path,
            token=token,
            headers=headers,
            params=params,
            correlation_id=correlation_id,
            source_ip=source_ip,
        )

    async def post(
        self,
        path: str,
        *,
        token: str | None = None,
        json: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        """Convenience method for POST requests (never auto-retried)."""
        return await self.request(
            "POST",
            path,
            token=token,
            json=json,
            data=data,
            headers=headers,
            correlation_id=correlation_id,
            source_ip=source_ip,
        )

    async def put(
        self,
        path: str,
        *,
        token: str | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        """Convenience method for PUT requests."""
        return await self.request(
            "PUT",
            path,
            token=token,
            json=json,
            headers=headers,
            correlation_id=correlation_id,
            source_ip=source_ip,
        )

    async def delete(
        self,
        path: str,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> GatewayResponse:
        """Convenience method for DELETE requests."""
        return await self.request(
            "DELETE",
            path,
            token=token,
            headers=headers,
            correlation_id=correlation_id,
            source_ip=source_ip,
        )

    async def aclose(self) -> None:
        """Closes the underlying HTTP client session."""
        if not self._custom_client and not self._client.is_closed:
            await self._client.aclose()

    async def __aenter__(self) -> GatewayClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

