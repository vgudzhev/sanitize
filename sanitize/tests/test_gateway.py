"""Tests for gateway mode: proxy scrubbing + rehydration."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from sanitize.gateway import (
    GatewayVault,
    StreamRehydrator,
    _scrub_text,
    _scrub_value,
    _rehydrate_value,
    _get_policy,
    _sessions,
    _sessions_lock,
    gateway,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz3tXKJKL3c5Rm9vR0xN7bCSMUhJ3JM3hCzONv1V5qm0NYEBqF8IXE1DGJhT
kBwLpKQHq0mZpFmFYR1R8G4tX9s2hGzLHi7MRGfYQUuI/W6mCM+aX1ah43W8FgP+Q
8lL8gFx6bKfBTr5qkHb+3sGH+6m4wXi5vQXaQA5f0b/8J8Hhd9UKB+s1mZBpObnC/
DgfJ3Cu+0Y8AQXNG8gxNB3RhKO3EdRr5d0pS0U8sGfkIwdxiQ0w2rC7hZ0J7NEXYZ
VN5LT3tQsb9aMvPq/wXZcGJKs0mFjXnUxOwdQIDAQAB
-----END RSA PRIVATE KEY-----"""

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_DB_URL = "postgres://admin:s3cret@db.internal:5432/prod"


@pytest.fixture()
def vault():
    return GatewayVault()


@pytest.fixture(autouse=True)
def _clear_sessions():
    with _sessions_lock:
        _sessions.clear()
    yield
    with _sessions_lock:
        _sessions.clear()


@pytest.fixture()
async def client():
    transport = ASGITransport(app=gateway)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Vault unit tests
# ---------------------------------------------------------------------------

class TestGatewayVault:
    def test_placeholder_creation(self, vault: GatewayVault):
        p = vault.get_placeholder("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY")
        assert p == "[[AWS_ACCESS_KEY_1]]"

    def test_same_value_returns_same_placeholder(self, vault: GatewayVault):
        p1 = vault.get_placeholder("secret1", "GENERIC_SECRET")
        p2 = vault.get_placeholder("secret1", "GENERIC_SECRET")
        assert p1 == p2

    def test_different_values_increment(self, vault: GatewayVault):
        p1 = vault.get_placeholder("a", "EMAIL")
        p2 = vault.get_placeholder("b", "EMAIL")
        assert p1 == "[[EMAIL_1]]"
        assert p2 == "[[EMAIL_2]]"

    def test_rehydrate(self, vault: GatewayVault):
        vault.get_placeholder("real@email.com", "EMAIL")
        result = vault.rehydrate("Contact [[EMAIL_1]] for info")
        assert result == "Contact real@email.com for info"

    def test_rehydrate_unknown_placeholder_unchanged(self, vault: GatewayVault):
        result = vault.rehydrate("[[UNKNOWN_99]]")
        assert result == "[[UNKNOWN_99]]"


# ---------------------------------------------------------------------------
# Scrub / rehydrate
# ---------------------------------------------------------------------------

class TestScrubRehydrate:
    def test_scrub_text_detects_aws_key(self, vault: GatewayVault):
        policy = _get_policy()
        result = _scrub_text(f"key is {FAKE_AWS_KEY}", vault, policy)
        assert FAKE_AWS_KEY not in result
        assert "[[AWS_ACCESS_KEY_1]]" in result

    def test_scrub_value_recursive(self, vault: GatewayVault):
        policy = _get_policy()
        data = {
            "messages": [
                {"role": "user", "content": f"key {FAKE_AWS_KEY}"},
            ],
        }
        scrubbed = _scrub_value(data, vault, policy)
        content = scrubbed["messages"][0]["content"]
        assert FAKE_AWS_KEY not in content
        assert "[[AWS_ACCESS_KEY_1]]" in content

    def test_scrub_value_handles_content_blocks(self, vault: GatewayVault):
        policy = _get_policy()
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": f"key {FAKE_AWS_KEY}"},
                    ],
                },
            ],
        }
        scrubbed = _scrub_value(data, vault, policy)
        text = scrubbed["messages"][0]["content"][0]["text"]
        assert FAKE_AWS_KEY not in text

    def test_scrub_tool_descriptions(self, vault: GatewayVault):
        policy = _get_policy()
        data = {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "connect",
                        "description": f"Connect to {FAKE_DB_URL}",
                    },
                },
            ],
        }
        scrubbed = _scrub_value(data, vault, policy)
        desc = scrubbed["tools"][0]["function"]["description"]
        assert "s3cret" not in desc

    def test_rehydrate_value_recursive(self, vault: GatewayVault):
        vault.get_placeholder(FAKE_AWS_KEY, "AWS_ACCESS_KEY")
        data = {
            "choices": [
                {
                    "message": {
                        "content": "The key is [[AWS_ACCESS_KEY_1]]",
                        "tool_calls": [
                            {
                                "function": {
                                    "arguments": '{"key": "[[AWS_ACCESS_KEY_1]]"}',
                                },
                            },
                        ],
                    },
                },
            ],
        }
        rehydrated = _rehydrate_value(data, vault)
        assert FAKE_AWS_KEY in rehydrated["choices"][0]["message"]["content"]
        assert FAKE_AWS_KEY in rehydrated["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]


# ---------------------------------------------------------------------------
# Stream rehydrator
# ---------------------------------------------------------------------------

class TestStreamRehydrator:
    def test_complete_placeholder(self, vault: GatewayVault):
        vault.get_placeholder("secret", "KEY")
        r = StreamRehydrator(vault)
        assert r.feed("[[KEY_1]]") == "secret"

    def test_split_placeholder(self, vault: GatewayVault):
        vault.get_placeholder("secret", "KEY")
        r = StreamRehydrator(vault)
        assert r.feed("hello [[KE") == "hello "
        assert r.feed("Y_1]]") == "secret"

    def test_split_across_three_chunks(self, vault: GatewayVault):
        vault.get_placeholder("secret", "KEY")
        r = StreamRehydrator(vault)
        assert r.feed("[[") == ""
        assert r.feed("KEY") == ""
        assert r.feed("_1]] end") == "secret end"

    def test_not_a_placeholder_long_buffer(self, vault: GatewayVault):
        r = StreamRehydrator(vault)
        long = "[[" + "A" * 70
        result = r.feed(long)
        assert result == long

    def test_flush(self, vault: GatewayVault):
        vault.get_placeholder("secret", "KEY")
        r = StreamRehydrator(vault)
        emitted = r.feed("partial [[KEY_")
        assert emitted == "partial "
        leftover = r.flush()
        assert leftover == "[[KEY_"

    def test_mixed_text_and_placeholders(self, vault: GatewayVault):
        vault.get_placeholder("alice@co.com", "EMAIL")
        vault.get_placeholder("AKIA1234567890ABCDEF", "AWS_KEY")
        r = StreamRehydrator(vault)
        full = r.feed("Contact [[EMAIL_1]] about [[AWS_KEY_1]]")
        assert full == "Contact alice@co.com about AKIA1234567890ABCDEF"


# ---------------------------------------------------------------------------
# Integration: full proxy round-trip
# ---------------------------------------------------------------------------

class TestProxySyncRoundTrip:
    """Non-streaming proxy: scrub request, rehydrate response."""

    @pytest.mark.asyncio
    async def test_aws_key_scrubbed_and_rehydrated(self, client: AsyncClient):
        openai_response = {
            "id": "chatcmpl-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "The key [[AWS_ACCESS_KEY_1]] is valid.",
                    },
                },
            ],
        }

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            assert FAKE_AWS_KEY not in json.dumps(body), "Secret leaked to upstream"
            return httpx.Response(200, json=openai_response)

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "user", "content": f"My key is {FAKE_AWS_KEY}"},
                    ],
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert FAKE_AWS_KEY in data["choices"][0]["message"]["content"]
        assert "x-sanitize-session" in resp.headers

    @pytest.mark.asyncio
    async def test_pem_key_scrubbed_and_rehydrated(self, client: AsyncClient):
        """Round-trip a multi-line PEM private key — the discriminating test."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            body_str = json.dumps(body)
            assert "BEGIN RSA PRIVATE KEY" not in body_str
            assert "MIIEpAIBAAK" not in body_str
            placeholder_found = "[[PRIVATE_KEY" in body_str or "[[RSA_PRIVATE_KEY" in body_str
            assert placeholder_found, f"Expected placeholder in upstream body, got: {body_str[:200]}"
            return httpx.Response(200, json={
                "choices": [{"message": {"role": "assistant", "content": "I see the key"}}],
            })

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [
                        {"role": "user", "content": f"Here is my key:\n{FAKE_PEM}"},
                    ],
                },
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_anthropic_format(self, client: AsyncClient):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            assert FAKE_AWS_KEY not in json.dumps(body)
            return httpx.Response(200, json={
                "content": [{"type": "text", "text": "The key [[AWS_ACCESS_KEY_1]] works."}],
            })

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.post(
                "/anthropic/v1/messages",
                json={
                    "model": "claude-3-opus",
                    "messages": [
                        {"role": "user", "content": f"key {FAKE_AWS_KEY}"},
                    ],
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert FAKE_AWS_KEY in data["content"][0]["text"]


class TestProxyStreamingRoundTrip:
    """Streaming proxy: scrub request, rehydrate SSE deltas."""

    @pytest.mark.asyncio
    async def test_streaming_rehydration(self, client: AsyncClient):
        chunks = [
            'data: {"id":"1","choices":[{"delta":{"content":"The key is [["}}]}\n\n',
            'data: {"id":"1","choices":[{"delta":{"content":"AWS_ACCESS"}}]}\n\n',
            'data: {"id":"1","choices":[{"delta":{"content":"_KEY_1]] ok"}}]}\n\n',
            "data: [DONE]\n\n",
        ]

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            assert FAKE_AWS_KEY not in json.dumps(body)
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(
                    "".join(chunks).encode(),
                ),
            )

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "stream": True,
                    "messages": [
                        {"role": "user", "content": f"My key is {FAKE_AWS_KEY}"},
                    ],
                },
            )

        assert resp.status_code == 200
        body = resp.text
        assert FAKE_AWS_KEY in body

    @pytest.mark.asyncio
    async def test_pem_streaming_round_trip(self, client: AsyncClient):
        """PEM key through streaming — the advisor's discriminating test."""

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body_str = json.dumps(json.loads(request.content))
            assert "BEGIN RSA PRIVATE KEY" not in body_str, "PEM leaked to upstream"
            chunks = [
                'data: {"id":"1","choices":[{"delta":{"content":"Got it"}}]}\n\n',
                "data: [DONE]\n\n",
            ]
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream("".join(chunks).encode()),
            )

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "stream": True,
                    "messages": [
                        {"role": "user", "content": f"Key:\n{FAKE_PEM}"},
                    ],
                },
            )
        assert resp.status_code == 200


class TestNoContentLogging:
    """Gateway must never log request/response bodies."""

    @pytest.mark.asyncio
    async def test_gateway_does_not_log_secrets(self, client: AsyncClient, caplog):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        secret = "MySuperUniqueGatewaySecret999XYZ"
        with patch("sanitize.gateway._http_client", mock_client):
            with caplog.at_level("DEBUG"):
                await client.post(
                    "/openai/v1/chat/completions",
                    json={
                        "model": "gpt-4",
                        "messages": [{"role": "user", "content": f"password={secret}"}],
                    },
                )
        for record in caplog.records:
            assert secret not in record.getMessage()


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_unknown_provider_returns_400(self, client: AsyncClient):
        resp = await client.post(
            "/badprovider/v1/chat/completions",
            json={"messages": []},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_json_returns_400(self, client: AsyncClient):
        resp = await client.post(
            "/openai/v1/chat/completions",
            content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_session_persistence(self, client: AsyncClient):
        """Same session ID reuses the same vault."""

        responses = []

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            responses.append(json.dumps(body))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            r1 = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": f"key {FAKE_AWS_KEY}"}],
                },
                headers={"x-sanitize-session": "sess-1"},
            )
            r2 = await client.post(
                "/openai/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": f"again {FAKE_AWS_KEY}"}],
                },
                headers={"x-sanitize-session": "sess-1"},
            )

        assert r1.headers["x-sanitize-session"] == "sess-1"
        assert r2.headers["x-sanitize-session"] == "sess-1"
        assert "[[AWS_ACCESS_KEY_1]]" in responses[0]
        assert "[[AWS_ACCESS_KEY_1]]" in responses[1]

    @pytest.mark.asyncio
    async def test_health_endpoint(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mode"] == "gateway"

    @pytest.mark.asyncio
    async def test_get_passthrough(self, client: AsyncClient):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": [{"id": "gpt-4"}]})

        mock_transport = httpx.MockTransport(mock_handler)
        mock_client = httpx.AsyncClient(transport=mock_transport)

        with patch("sanitize.gateway._http_client", mock_client):
            resp = await client.get("/openai/v1/models")
        assert resp.status_code == 200
        assert resp.json()["data"][0]["id"] == "gpt-4"
