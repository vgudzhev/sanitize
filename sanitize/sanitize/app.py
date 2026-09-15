"""FastAPI service: /v1/detect, /v1/health, /v1/policy."""

from __future__ import annotations

from datetime import date

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import engine
from .policy import load_policy

app = FastAPI(title="sanitize", version="0.1.0")

_policy_config: dict | None = None
_policy_version: str = date.today().isoformat() + ".1"


def _get_policy() -> dict:
    global _policy_config
    if _policy_config is None:
        _policy_config = load_policy()
    return _policy_config


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


@app.post("/v1/detect", response_model=DetectResponse)
async def detect(req: DetectRequest) -> DetectResponse:
    policy = _get_policy()
    spans, stats = engine.detect(req.text, req.hints, policy)
    return DetectResponse(
        spans=[SpanResult(start=s.start, end=s.end, type=s.type, score=s.score, detector=s.detector) for s in spans],
        stats=stats,
        policy_version=_policy_version,
    )


@app.get("/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    policy = _get_policy()
    _, detectors = engine._get_analyzer(policy)
    return HealthResponse(status="ok", version="0.1.0", detectors=detectors)


@app.get("/v1/policy")
async def policy() -> dict:
    return _get_policy()
