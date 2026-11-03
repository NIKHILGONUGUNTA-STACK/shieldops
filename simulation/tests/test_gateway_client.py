"""Tests for Gateway HTTP Client."""

import httpx
import pytest
import respx

from simulation.clients.gateway import (
    GatewayClient,
    GatewayClientError,
    GatewayTimeoutError,
)
from simulation.config import GatewayConfig


@pytest.fixture
def gateway_config():
    return GatewayConfig(
        base_url="http://localhost:8000",
        timeout_seconds=2.0,
        max_retries=2,
        allow_synthetic_source_ip=False,
    )


@pytest.mark.asyncio
@respx.mock
async def test_get_request_success(gateway_config):
    route = respx.get("http://localhost:8000/api/v1/customers/cust-1").mock(
        return_value=httpx.Response(
            200,
            json={"id": "cust-1", "name": "Alex"},
            headers={"Content-Type": "application/json"},
        )
    )

    client = GatewayClient(gateway_config)
    try:
        resp = await client.get("/api/v1/customers/cust-1", token="test-token")
        assert resp.status_code == 200
        assert resp.is_success is True
        assert resp.json() == {"id": "cust-1", "name": "Alex"}
        assert resp.duration_ms > 0
        assert resp.correlation_id is not None

        # Verify sent headers
        sent_request = route.calls.last.request
        assert sent_request.headers["Authorization"] == "Bearer test-token"
        assert sent_request.headers["X-Correlation-Id"] == resp.correlation_id
        assert "X-Forwarded-For" not in sent_request.headers
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_post_request_never_auto_retried(gateway_config):
    route = respx.post("http://localhost:8000/api/v1/transfers").mock(
        return_value=httpx.Response(502, text="Bad Gateway")
    )

    client = GatewayClient(gateway_config)
    try:
        # Transfer requests are non-idempotent: must NEVER be retried automatically
        resp = await client.post("/api/v1/transfers", json={"amount": 100})
        assert resp.status_code == 502
        assert route.call_count == 1  # Exactly 1 call, zero automatic retries
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_request_retries_transient_502(gateway_config):
    route = respx.get("http://localhost:8000/api/v1/accounts").mock(
        side_effect=[
            httpx.Response(502, text="Bad Gateway"),
            httpx.Response(200, json=[{"id": "acct-1"}]),
        ]
    )

    client = GatewayClient(gateway_config)
    try:
        resp = await client.get("/api/v1/accounts")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "acct-1"}]
        assert route.call_count == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_request_exhausts_retries(gateway_config):
    route = respx.get("http://localhost:8000/api/v1/accounts").mock(
        return_value=httpx.Response(503, text="Service Unavailable")
    )

    client = GatewayClient(gateway_config)
    try:
        resp = await client.get("/api/v1/accounts")
        assert resp.status_code == 503
        # 1 initial + 2 retries = 3 calls
        assert route.call_count == 3
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_post_timeout_raises_error(gateway_config):
    respx.post("http://localhost:8000/api/v1/transfers").mock(
        side_effect=httpx.TimeoutException("Read timed out")
    )

    client = GatewayClient(gateway_config)
    try:
        with pytest.raises(GatewayTimeoutError) as exc_info:
            await client.post("/api/v1/transfers", json={"amount": 50})
        assert "timed out" in str(exc_info.value)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_synthetic_source_ip_rejected_when_disabled(gateway_config):
    client = GatewayClient(gateway_config)
    try:
        with pytest.raises(GatewayClientError) as exc_info:
            await client.get("/api/v1/customers", source_ip="198.51.100.42")
        assert "synthetic source IP injection is disabled" in str(exc_info.value)
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_synthetic_source_ip_allowed_when_enabled():
    config = GatewayConfig(
        base_url="http://localhost:8000",
        allow_synthetic_source_ip=True,
    )
    route = respx.get("http://localhost:8000/api/v1/customers").mock(
        return_value=httpx.Response(200, json=[])
    )

    client = GatewayClient(config)
    try:
        resp = await client.get("/api/v1/customers", source_ip="198.51.100.42")
        assert resp.status_code == 200
        sent_req = route.calls.last.request
        assert sent_req.headers["X-Forwarded-For"] == "198.51.100.42"
    finally:
        await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_explicit_correlation_id_preserved(gateway_config):
    respx.get("http://localhost:8000/api/v1/customers").mock(
        return_value=httpx.Response(200, json=[])
    )

    client = GatewayClient(gateway_config)
    try:
        resp = await client.get("/api/v1/customers", correlation_id="custom-cid-12345")
        assert resp.correlation_id == "custom-cid-12345"
    finally:
        await client.aclose()
