"""FastAPI service: /v1/detect, /v1/health, /v1/policy, /v1/metrics."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections import defaultdict
from datetime import date
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from . import engine
from .policy import load_policy

log = logging.getLogger(__name__)

@asynccontextmanager
async def _lifespan(app: FastAPI):
    _load_signed_policy()
    yield

app = FastAPI(title="sanitize", version="0.2.0", lifespan=_lifespan)

_policy_config: dict | None = None
_policy_version: str = date.today().isoformat() + ".1"
_signed_policy_blob: bytes | None = None
_signed_policy_signature: str | None = None
_signed_policy_key_id: str | None = None

_BEARER_TOKEN: str | None = os.environ.get("SANITIZE_TOKEN")


def _get_policy() -> dict:
    global _policy_config
    if _policy_config is None:
        _policy_config = load_policy()
    return _policy_config


def _load_signed_policy() -> None:
    """Load pre-signed policy from disk if available."""
    global _signed_policy_blob, _signed_policy_signature, _signed_policy_key_id, _policy_config, _policy_version
    signed_dir = Path(os.environ.get("SANITIZE_POLICY_DIR", ""))
    if not signed_dir.is_dir():
        return
    policy_file = signed_dir / "policy.json"
    sig_file = signed_dir / "policy.sig"
    key_id_file = signed_dir / "key_id"
    if not policy_file.is_file() or not sig_file.is_file():
        return
    try:
        _signed_policy_blob = policy_file.read_bytes()
        _signed_policy_signature = sig_file.read_text().strip()
        _signed_policy_key_id = key_id_file.read_text().strip() if key_id_file.is_file() else "default"
        _policy_config = load_policy(central_policy=json.loads(_signed_policy_blob))
        fp = hashlib.sha256(_signed_policy_blob).hexdigest()[:16]
        _policy_version = f"{date.today().isoformat()}.{fp}"
        log.info("Loaded signed policy (key_id=%s)", _signed_policy_key_id)
    except Exception:
        log.warning("Failed to load signed policy", exc_info=True)




def _verify_token(request: Request) -> None:
    if _BEARER_TOKEN is None:
        return
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if auth[7:] != _BEARER_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


class DetectRequest(BaseModel):
    text: str
    hints: dict = Field(default_factory=dict)
    policy: str = "default"


class SpanResult(BaseModel):
    start: int
    end: int
    type: str
    score: float
    detector: str


class DetectResponse(BaseModel):
    spans: list[SpanResult]
    stats: dict
    policy_version: str


class HealthResponse(BaseModel):
    status: str
    version: str
    detectors: list[str]


_metrics_lock = threading.Lock()
_metrics: dict[str, int] = defaultdict(int)
_metrics_requests: int = 0


def _record_metrics(spans: list) -> None:
    global _metrics_requests
    with _metrics_lock:
        _metrics_requests += 1
        for s in spans:
            _metrics[s.type] += 1


@app.post("/v1/detect", response_model=DetectResponse, dependencies=[Depends(_verify_token)])
async def detect(req: DetectRequest) -> DetectResponse:
    policy = _get_policy()
    spans, stats = engine.detect(req.text, req.hints, policy)
    _record_metrics(spans)
    return DetectResponse(
        spans=[SpanResult(start=s.start, end=s.end, type=s.type, score=s.score, detector=s.detector) for s in spans],
        stats=stats,
        policy_version=_policy_version,
    )


@app.get("/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    policy = _get_policy()
    _, detectors, _, _ = engine._get_analyzer(policy)
    return HealthResponse(status="ok", version="0.2.0", detectors=detectors)


@app.get("/v1/policy", dependencies=[Depends(_verify_token)])
async def policy() -> dict:
    base = _get_policy()
    result: dict = {"policy": base, "policy_version": _policy_version}
    if _signed_policy_signature:
        result["signature"] = _signed_policy_signature
        result["key_id"] = _signed_policy_key_id
    return result


@app.get("/v1/metrics", dependencies=[Depends(_verify_token)])
async def metrics() -> dict:
    with _metrics_lock:
        return {
            "requests": _metrics_requests,
            "categories": dict(_metrics),
            "policy_version": _policy_version,
        }
