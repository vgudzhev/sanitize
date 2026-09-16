"""Gateway mode: OpenAI-/Anthropic-compatible proxy with scrubbing.

Local sidecar — binds 127.0.0.1 only, separate from the org service.
The vault lives in-process for the lifetime of each session.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from . import engine
from .policy import load_policy

log = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\[\[[A-Z_]+_\d+\]\]")
_MAX_PLACEHOLDER_LEN = 64


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class GatewayVault:
    """Per-session mapping between real values and stable placeholders."""

    def __init__(self) -> None:
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.counters: dict[str, int] = defaultdict(int)

    def get_placeholder(self, value: str, span_type: str) -> str:
        existing = self.reverse.get(value)
        if existing is not None:
            return existing
        self.counters[span_type] += 1
        placeholder = f"[[{span_type}_{self.counters[span_type]}]]"
        self.forward[placeholder] = value
        self.reverse[value] = placeholder
        return placeholder

    def rehydrate(self, text: str) -> str:
        return _PLACEHOLDER_RE.sub(
            lambda m: self.forward.get(m.group(), m.group()),
            text,
        )


# ---------------------------------------------------------------------------
# Session store (thread-safe, TTL-based cleanup)
# ---------------------------------------------------------------------------

_SESSION_TTL = 3600
_sessions_lock = threading.Lock()
_sessions: dict[str, tuple[GatewayVault, float]] = {}


def _get_vault(session_id: str) -> GatewayVault:
    with _sessions_lock:
        entry = _sessions.get(session_id)
        if entry is not None:
            vault, _ = entry
            _sessions[session_id] = (vault, time.monotonic())
            return vault
        vault = GatewayVault()
        _sessions[session_id] = (vault, time.monotonic())
        return vault


def _cleanup_sessions() -> None:
    cutoff = time.monotonic() - _SESSION_TTL
    with _sessions_lock:
        expired = [k for k, (_, ts) in _sessions.items() if ts < cutoff]
        for k in expired:
            del _sessions[k]


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

_policy_config: dict | None = None


def _get_policy() -> dict:
    global _policy_config
    if _policy_config is None:
        _policy_config = load_policy()
    return _policy_config


# ---------------------------------------------------------------------------
# Scrub / rehydrate helpers
# ---------------------------------------------------------------------------

def _scrub_text(text: str, vault: GatewayVault, policy: dict) -> str:
    if not text:
        return text
    spans, _ = engine.detect(text, {}, policy)
    if not spans:
        return text
    sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)
    result = text
    for span in sorted_spans:
        value = result[span.start : span.end]
        placeholder = vault.get_placeholder(value, span.type)
        result = result[: span.start] + placeholder + result[span.end :]
    return result


def _scrub_value(value: object, vault: GatewayVault, policy: dict) -> object:
    """Recursively scrub all strings in a JSON-like structure."""
    if isinstance(value, str):
        return _scrub_text(value, vault, policy)
    if isinstance(value, list):
        return [_scrub_value(v, vault, policy) for v in value]
    if isinstance(value, dict):
        return {k: _scrub_value(v, vault, policy) for k, v in value.items()}
    return value


def _rehydrate_value(value: object, vault: GatewayVault) -> object:
    """Recursively rehydrate placeholders in a JSON-like structure."""
    if isinstance(value, str):
        return vault.rehydrate(value)
    if isinstance(value, list):
        return [_rehydrate_value(v, vault) for v in value]
    if isinstance(value, dict):
        return {k: _rehydrate_value(v, vault) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# Stream rehydrator (handles placeholders split across SSE chunks)
# ---------------------------------------------------------------------------

class StreamRehydrator:
    """Buffers text so placeholders split across chunks are rehydrated correctly."""

    def __init__(self, vault: GatewayVault) -> None:
        self.vault = vault
        self.pending = ""

    def feed(self, text: str) -> str:
        self.pending += text
        safe_end = len(self.pending)
        last_open = self.pending.rfind("[[")
        if last_open != -1:
            close_after = self.pending.find("]]", last_open)
            if close_after == -1 and len(self.pending) - last_open <= _MAX_PLACEHOLDER_LEN:
                safe_end = last_open
        if safe_end == 0:
            return ""
        emit = self.pending[:safe_end]
        self.pending = self.pending[safe_end:]
        return self.vault.rehydrate(emit)

    def flush(self) -> str:
        result = self.vault.rehydrate(self.pending)
        self.pending = ""
        return result


# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------

_UPSTREAMS: dict[str, str] = {
    "openai": os.environ.get("SANITIZE_GATEWAY_OPENAI_URL", "https://api.openai.com"),
    "anthropic": os.environ.get("SANITIZE_GATEWAY_ANTHROPIC_URL", "https://api.anthropic.com"),
}

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host",
    "content-length", "content-encoding",
})


def _forward_headers(request: Request) -> dict[str, str]:
    return {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }


# ---------------------------------------------------------------------------
# SSE delta extraction/injection per provider
# ---------------------------------------------------------------------------

def _extract_openai_delta(data: dict) -> str | None:
    try:
        choices = data.get("choices", [])
        if choices and "delta" in choices[0]:
            return choices[0]["delta"].get("content")
    except (IndexError, TypeError, KeyError):
        pass
    return None


def _inject_openai_delta(data: dict, text: str) -> dict:
    data = json.loads(json.dumps(data))
    try:
        data["choices"][0]["delta"]["content"] = text
    except (IndexError, TypeError, KeyError):
        pass
    return data


def _extract_anthropic_delta(data: dict) -> str | None:
    try:
        if data.get("type") == "content_block_delta":
            delta = data.get("delta", {})
            if delta.get("type") == "text_delta":
                return delta.get("text")
    except (TypeError, KeyError):
        pass
    return None


def _inject_anthropic_delta(data: dict, text: str) -> dict:
    data = json.loads(json.dumps(data))
    try:
        data["delta"]["text"] = text
    except (TypeError, KeyError):
        pass
    return data


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def _lifespan(a: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0))
    _get_policy()
    yield
    await _http_client.aclose()
    _http_client = None


gateway = FastAPI(title="sanitize-gateway", version="0.1.0", lifespan=_lifespan)


@gateway.get("/health")
async def health():
    _cleanup_sessions()
    return {"status": "ok", "mode": "gateway", "sessions": len(_sessions)}


@gateway.api_route("/{provider}/{path:path}", methods=["POST"])
async def proxy(request: Request, provider: str, path: str):
    upstream_base = _UPSTREAMS.get(provider)
    if upstream_base is None:
        return Response(
            content=json.dumps({"error": f"Unknown provider: {provider}"}),
            status_code=400,
            media_type="application/json",
        )

    session_id = request.headers.get("x-sanitize-session") or str(uuid.uuid4())
    vault = _get_vault(session_id)
    policy = _get_policy()

    body_bytes = await request.body()
    try:
        body = json.loads(body_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Response(
            content=json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            media_type="application/json",
        )

    is_streaming = body.get("stream", False)
    scrubbed_body = _scrub_value(body, vault, policy)

    upstream_url = f"{upstream_base}/{path}"
    headers = _forward_headers(request)
    headers["content-type"] = "application/json"

    assert _http_client is not None

    if is_streaming:
        return await _proxy_streaming(upstream_url, headers, scrubbed_body, vault, provider, session_id)
    else:
        return await _proxy_sync(upstream_url, headers, scrubbed_body, vault, session_id)


async def _proxy_sync(
    url: str, headers: dict, body: dict, vault: GatewayVault, session_id: str,
) -> Response:
    assert _http_client is not None
    resp = await _http_client.post(url, headers=headers, json=body)
    try:
        resp_body = resp.json()
        rehydrated = _rehydrate_value(resp_body, vault)
        content = json.dumps(rehydrated)
    except (json.JSONDecodeError, UnicodeDecodeError):
        content = resp.text

    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    resp_headers["x-sanitize-session"] = session_id
    return Response(
        content=content,
        status_code=resp.status_code,
        headers=resp_headers,
        media_type="application/json",
    )


async def _proxy_streaming(
    url: str, headers: dict, body: dict, vault: GatewayVault,
    provider: str, session_id: str,
) -> StreamingResponse:

    extract_delta = _extract_openai_delta if provider == "openai" else _extract_anthropic_delta
    inject_delta = _inject_openai_delta if provider == "openai" else _inject_anthropic_delta

    assert _http_client is not None
    upstream_resp = await _http_client.send(
        _http_client.build_request("POST", url, headers=headers, json=body),
        stream=True,
    )

    rehydrator = StreamRehydrator(vault)

    async def event_stream():
        try:
            async for raw_line in upstream_resp.aiter_lines():
                if not raw_line.startswith("data: "):
                    yield raw_line + "\n"
                    continue
                data_str = raw_line[6:].strip()
                if data_str == "[DONE]":
                    leftover = rehydrator.flush()
                    if leftover:
                        stub = {"choices": [{"delta": {"content": leftover}}]} if provider == "openai" else {
                            "type": "content_block_delta",
                            "delta": {"type": "text_delta", "text": leftover},
                        }
                        yield f"data: {json.dumps(stub)}\n\n"
                    yield raw_line + "\n\n"
                    continue

                try:
                    data = json.loads(data_str)
                except json.JSONDecodeError:
                    yield raw_line + "\n"
                    continue

                text = extract_delta(data)
                if text is not None:
                    rehydrated_text = rehydrator.feed(text)
                    if rehydrated_text:
                        modified = inject_delta(data, rehydrated_text)
                        yield f"data: {json.dumps(modified)}\n\n"
                    # else: text is buffered, skip this chunk
                else:
                    data = _rehydrate_value(data, vault)
                    yield f"data: {json.dumps(data)}\n\n"
        finally:
            await upstream_resp.aclose()

    resp_headers = {"x-sanitize-session": session_id}
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers=resp_headers,
    )


# ---------------------------------------------------------------------------
# Passthrough for non-POST routes (list models, etc.)
# ---------------------------------------------------------------------------

@gateway.api_route("/{provider}/{path:path}", methods=["GET", "DELETE"])
async def proxy_passthrough(request: Request, provider: str, path: str):
    upstream_base = _UPSTREAMS.get(provider)
    if upstream_base is None:
        return Response(
            content=json.dumps({"error": f"Unknown provider: {provider}"}),
            status_code=400,
            media_type="application/json",
        )
    assert _http_client is not None
    upstream_url = f"{upstream_base}/{path}"
    headers = _forward_headers(request)
    resp = await _http_client.request(request.method, upstream_url, headers=headers)
    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers,
        media_type=resp.headers.get("content-type", "application/json"),
    )
