"""Tests for Phase 4: /v1/metrics, bearer auth, signed policy."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from sanitize.app import app, _metrics, _metrics_lock, _metrics_requests


@pytest.fixture()
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def reset_metrics():
    global _metrics_requests
    import sanitize.app as app_mod
    with app_mod._metrics_lock:
        app_mod._metrics.clear()
        app_mod._metrics_requests = 0
    yield


class TestMetricsEndpoint:
    @pytest.mark.asyncio
    async def test_metrics_empty(self, client):
        resp = await client.get("/v1/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert data["requests"] == 0
        assert data["categories"] == {}
        assert "policy_version" in data

    @pytest.mark.asyncio
    async def test_metrics_after_detect(self, client):
        await client.post("/v1/detect", json={
            "text": "key AKIAIOSFODNN7EXAMPLE here",
            "hints": {},
        })
        resp = await client.get("/v1/metrics")
        data = resp.json()
        assert data["requests"] == 1
        assert data["categories"].get("AWS_ACCESS_KEY", 0) >= 1

    @pytest.mark.asyncio
    async def test_metrics_counts_accumulate(self, client):
        for _ in range(3):
            await client.post("/v1/detect", json={
                "text": "key AKIAIOSFODNN7EXAMPLE here",
                "hints": {},
            })
        resp = await client.get("/v1/metrics")
        data = resp.json()
        assert data["requests"] == 3


class TestBearerAuth:
    @pytest.mark.asyncio
    async def test_no_token_required_when_unset(self, client):
        resp = await client.post("/v1/detect", json={
            "text": "hello world",
            "hints": {},
        })
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_token_required_when_set(self):
        import sanitize.app as app_mod
        original = app_mod._BEARER_TOKEN
        try:
            app_mod._BEARER_TOKEN = "test-secret-token"
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.post("/v1/detect", json={
                    "text": "hello",
                    "hints": {},
                })
                assert resp.status_code == 401

                resp = await c.post("/v1/detect", json={
                    "text": "hello",
                    "hints": {},
                }, headers={"Authorization": "Bearer wrong-token"})
                assert resp.status_code == 403

                resp = await c.post("/v1/detect", json={
                    "text": "hello",
                    "hints": {},
                }, headers={"Authorization": "Bearer test-secret-token"})
                assert resp.status_code == 200
        finally:
            app_mod._BEARER_TOKEN = original

    @pytest.mark.asyncio
    async def test_health_does_not_require_token(self):
        import sanitize.app as app_mod
        original = app_mod._BEARER_TOKEN
        try:
            app_mod._BEARER_TOKEN = "test-secret-token"
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/v1/health")
                assert resp.status_code == 200
        finally:
            app_mod._BEARER_TOKEN = original


class TestPolicyEndpoint:
    @pytest.mark.asyncio
    async def test_policy_returns_version(self, client):
        resp = await client.get("/v1/policy")
        data = resp.json()
        assert "policy" in data
        assert "policy_version" in data

    @pytest.mark.asyncio
    async def test_policy_includes_signature_when_present(self):
        import sanitize.app as app_mod
        orig_sig = app_mod._signed_policy_signature
        orig_kid = app_mod._signed_policy_key_id
        try:
            app_mod._signed_policy_signature = "deadbeef"
            app_mod._signed_policy_key_id = "key123"
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as c:
                resp = await c.get("/v1/policy")
                data = resp.json()
                assert data["signature"] == "deadbeef"
                assert data["key_id"] == "key123"
        finally:
            app_mod._signed_policy_signature = orig_sig
            app_mod._signed_policy_key_id = orig_kid


class TestSignedPolicyMerge:
    """Verify _load_signed_policy routes through load_policy(central_policy=...)."""

    @pytest.mark.asyncio
    async def test_signed_policy_uses_tighten_merge(self, tmp_path):
        import json
        import sanitize.app as app_mod

        central = {
            "deny_paths": ["**/central-deny.txt"],
            "allow": ["example.com"],
            "detectors": {"gliner": {"threshold": 0.7}},
            "sanitize": {"fail_open": False},
        }
        canonical = json.dumps(central, sort_keys=True, separators=(",", ":"))

        (tmp_path / "policy.json").write_text(canonical)
        (tmp_path / "policy.sig").write_text("deadbeef")
        (tmp_path / "key_id").write_text("test123")

        orig_config = app_mod._policy_config
        orig_blob = app_mod._signed_policy_blob
        orig_sig = app_mod._signed_policy_signature
        orig_kid = app_mod._signed_policy_key_id
        orig_ver = app_mod._policy_version

        try:
            with patch.dict(os.environ, {"SANITIZE_POLICY_DIR": str(tmp_path)}):
                app_mod._load_signed_policy()
            policy = app_mod._policy_config
            assert "**/central-deny.txt" in policy["deny_paths"]
            assert policy["sanitize"]["fail_open"] is False
        finally:
            app_mod._policy_config = orig_config
            app_mod._signed_policy_blob = orig_blob
            app_mod._signed_policy_signature = orig_sig
            app_mod._signed_policy_key_id = orig_kid
            app_mod._policy_version = orig_ver


class TestNoContentLogging:
    """Phase 4 claim: service never logs request text."""

    @pytest.mark.asyncio
    async def test_detect_does_not_log_text(self, client, caplog):
        secret_text = "password=MySuperUniqueSecret12345XYZ"
        with caplog.at_level("DEBUG"):
            await client.post("/v1/detect", json={
                "text": secret_text,
                "hints": {},
            })
        for record in caplog.records:
            assert "MySuperUniqueSecret12345XYZ" not in record.getMessage()
