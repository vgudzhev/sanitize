"""Integration tests for the FastAPI endpoints."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from sanitize.app import app


@pytest.fixture()
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
    assert "gitleaks" in data["detectors"]


@pytest.mark.asyncio
async def test_detect_aws_key(client):
    resp = await client.post("/v1/detect", json={
        "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["spans"]) > 0
    types = {s["type"] for s in data["spans"]}
    assert "AWS_ACCESS_KEY" in types
    assert "policy_version" in data
    assert data["stats"]["detectors_run"]


@pytest.mark.asyncio
async def test_detect_private_key(client):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AEEk\n"
        "-----END RSA PRIVATE KEY-----"
    )
    resp = await client.post("/v1/detect", json={"text": text})
    assert resp.status_code == 200
    data = resp.json()
    types = {s["type"] for s in data["spans"]}
    assert "PRIVATE_KEY" in types


@pytest.mark.asyncio
async def test_detect_clean(client):
    resp = await client.post("/v1/detect", json={
        "text": "Hello, this is a normal message with no secrets.",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["spans"]) == 0


@pytest.mark.asyncio
async def test_policy_endpoint(client):
    resp = await client.get("/v1/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert "deny_paths" in data
    assert "allow" in data
