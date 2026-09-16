#!/usr/bin/env python3
"""Latency benchmark for sanitize detection.

§6 Phase 2 gate: p95 < 300ms for a 50KB tool result on CPU.

Calls sanitize.engine.detect() in-process (no HTTP) on synthetic tool_result
payloads at several sizes and reports p50/p95/p99 wall-clock latency per size.

Methodology notes:
- Payloads are deterministic (seeded) mixes of code, logs, and shell output
  with planted secrets roughly every ~2KB, so the chunk prefilter fires on
  most chunks and detection genuinely runs. This is a conservative workload.
- One untimed warm-up call per size absorbs one-off costs (analyzer build,
  spaCy / GLiNER model load) that a long-running service pays once.
- The engine's clean-chunk cache is cleared before every timed iteration so
  each run reflects a fresh, never-seen tool result. Pass --keep-cache to
  measure the warm-cache path instead.
- The LLM recognizer is forced off: it needs Ollama and is not part of the
  CPU latency budget.

Usage:
    cd sanitize && python ../evals/bench_latency.py
    cd evals && python bench_latency.py --iterations 100
"""

from __future__ import annotations

import argparse
import copy
import os
import random
import statistics
import sys
import time

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sanitize")
)

from sanitize import engine  # noqa: E402
from sanitize.engine import detect  # noqa: E402
from sanitize.policy import load_policy  # noqa: E402

DEFAULT_SIZES = [1024, 10240, 51200, 102400]
DEFAULT_ITERATIONS = 50
GATE_SIZE_BYTES = 51200
GATE_P95_MS = 300.0
SECRET_EVERY_BYTES = 2048


# --------------------------------------------------------------------------
# Payload generation
# --------------------------------------------------------------------------

_CODE_LINES = [
    "def {fn}({arg}: str) -> dict:",
    "    result = self._client.get(f\"/api/v1/{res}/{{{arg}}}\")",
    "    if result.status_code != 200:",
    "        raise RuntimeError(f\"unexpected status {{result.status_code}}\")",
    "    return result.json()",
    "",
    "export async function {fn}({arg}: string): Promise<{res}Response> {{",
    "  const res = await fetch(`${{BASE_URL}}/{res}/${{{arg}}}`);",
    "  if (!res.ok) throw new Error(`{res} fetch failed: ${{res.status}}`);",
    "  return res.json();",
    "}}",
    "",
    "for item in items:",
    "    cache[item.id] = normalize(item)",
    "logger.debug(\"processed %d items in %.2fs\", len(items), elapsed)",
    "class {res}Repository:",
    "    def __init__(self, session: Session) -> None:",
    "        self.session = session",
    "// TODO(review): tighten retry policy before enabling in prod",
    "# See docs/architecture.md §4 for the retry semantics",
    "    assert len(spans) == expected, f\"got {{len(spans)}}\"",
    "const {arg}Schema = z.object({{ id: z.string(), count: z.number() }});",
]

_LOG_LINES = [
    "2026-09-16T{hh}:{mm}:{ss}.{ms}Z INFO  {svc}: request completed path=/api/v1/{res} status=200 dur={dur}ms",
    "2026-09-16T{hh}:{mm}:{ss}.{ms}Z WARN  {svc}: retrying upstream call attempt={n} backoff={dur}ms",
    "2026-09-16T{hh}:{mm}:{ss}.{ms}Z DEBUG {svc}: cache miss key={res}:{n}",
    "2026-09-16T{hh}:{mm}:{ss}.{ms}Z ERROR {svc}: connection reset by peer (errno 104)",
    "[{hh}:{mm}:{ss}] worker-{n} picked job {res}-{n} from queue",
    "PASSED tests/test_{res}.py::test_{fn} ({dur}ms)",
    "FAILED tests/test_{res}.py::test_{fn}_edge - AssertionError",
    "npm WARN deprecated {res}@{n}.0.{n}: use {res}-next instead",
    "commit {sha}  Author: dev <dev@example.com>  Refactor {res} handling",
    "  modified:   src/{res}/{fn}.py",
    "  new file:   tests/test_{fn}.py",
    "-rw-r--r--  1 build build  {size} Sep 16 {hh}:{mm} {res}.log",
    "==> Compiling {res} ({n}/{n2})",
    "warning: unused variable `{arg}` (rustc W0612)",
]

_SVCS = ["api-gateway", "worker", "scheduler", "ingest", "billing", "auth"]
_RES = ["users", "orders", "invoices", "sessions", "tokens", "reports", "jobs"]
_FNS = ["fetch_record", "sync_batch", "resolve_owner", "apply_patch", "load_config"]
_ARGS = ["user_id", "order_id", "cursor", "payload", "opts"]

_ALPHANUM_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_B64URL = _ALPHANUM + "-_"


def _rand_str(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _planted_secret(rng: random.Random) -> str:
    """Return one line containing a realistic planted secret / PII item."""
    kind = rng.randrange(8)
    if kind == 0:
        return f"AWS_ACCESS_KEY_ID=AKIA{_rand_str(rng, _ALPHANUM_UPPER, 16)}"
    if kind == 1:
        return f"export GITHUB_TOKEN=ghp_{_rand_str(rng, _ALPHANUM, 36)}"
    if kind == 2:
        return f"Contact: {rng.choice(['alice', 'bob', 'carol'])}.{_rand_str(rng, 'abcdefghij', 5)}@corp-internal.io"
    if kind == 3:
        return f"db.host=10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
    if kind == 4:
        return (
            f"DATABASE_URL=postgres://svc_{_rand_str(rng, 'abcdef', 4)}:"
            f"{_rand_str(rng, _ALPHANUM, 18)}@db-{rng.randrange(1, 9)}.internal:5432/prod"
        )
    if kind == 5:
        return (
            f"Authorization: Bearer eyJ{_rand_str(rng, _B64URL, 24)}.eyJ"
            f"{_rand_str(rng, _B64URL, 40)}.{_rand_str(rng, _B64URL, 32)}"
        )
    if kind == 6:
        return f"STRIPE_KEY=sk_live_{_rand_str(rng, _ALPHANUM, 24)}"
    return f"password: {_rand_str(rng, _ALPHANUM, 20)}"


def _filler_line(rng: random.Random) -> str:
    tmpl = rng.choice(_CODE_LINES if rng.random() < 0.55 else _LOG_LINES)
    return tmpl.format(
        fn=rng.choice(_FNS),
        arg=rng.choice(_ARGS),
        res=rng.choice(_RES),
        svc=rng.choice(_SVCS),
        hh=f"{rng.randrange(24):02d}",
        mm=f"{rng.randrange(60):02d}",
        ss=f"{rng.randrange(60):02d}",
        ms=f"{rng.randrange(1000):03d}",
        dur=rng.randrange(1, 900),
        n=rng.randrange(1, 64),
        n2=rng.randrange(64, 128),
        sha=_rand_str(rng, "0123456789abcdef", 40),
        size=rng.randrange(1000, 999999),
    )


def generate_payload(target_bytes: int, seed: int = 0) -> str:
    """Build a deterministic, realistic tool_result payload of exactly target_bytes.

    Mix of code-like and log-like lines, with a planted secret roughly every
    SECRET_EVERY_BYTES bytes so detection actually runs on most chunks.
    """
    rng = random.Random(seed ^ target_bytes)
    lines: list[str] = []
    size = 0
    since_secret = 0
    while size < target_bytes:
        if since_secret >= SECRET_EVERY_BYTES:
            line = _planted_secret(rng)
            since_secret = 0
        else:
            line = _filler_line(rng)
        lines.append(line)
        size += len(line) + 1
        since_secret += len(line) + 1
    text = "\n".join(lines)
    # All generated text is ASCII, so len(text) == byte length.
    return text[:target_bytes]


# --------------------------------------------------------------------------
# Benchmark
# --------------------------------------------------------------------------


def bench(
    payload: str,
    iterations: int,
    policy: dict,
    clear_cache: bool = True,
) -> tuple[list[float], int]:
    """Time detect() over the payload. Returns (elapsed_ms per iteration, span count)."""
    # Untimed warm-up: builds the analyzer and loads models on first call.
    if clear_cache:
        engine._CLEAN_CHUNK_CACHE.clear()
    spans, _ = detect(payload, policy_config=policy)

    times: list[float] = []
    for _ in range(iterations):
        if clear_cache:
            engine._CLEAN_CHUNK_CACHE.clear()
        t0 = time.perf_counter()
        detect(payload, policy_config=policy)
        times.append((time.perf_counter() - t0) * 1000.0)
    return times, len(spans)


def percentile(values: list[float], pct: float) -> float:
    """Linear-interpolated percentile; works for any n >= 1."""
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _size_label(n: int) -> str:
    return f"{n // 1024}KB" if n % 1024 == 0 else f"{n}B"


def _gliner_status(policy: dict) -> str:
    analyzer, _, _, _ = engine._get_analyzer(policy)
    for rec in analyzer.registry.recognizers:
        if type(rec).__name__ == "GlinerRecognizer":
            if rec._available is True:
                return f"loaded ({rec.model_name})"
            if rec._available is False:
                return "unavailable (gliner/torch not installed or model load failed)"
            return "registered, not yet invoked"
    return "not registered"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--iterations", "-n", type=int, default=DEFAULT_ITERATIONS,
                    help=f"timed iterations per size (default {DEFAULT_ITERATIONS})")
    ap.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES,
                    help="payload sizes in bytes (default: 1KB 10KB 50KB 100KB)")
    ap.add_argument("--seed", type=int, default=0, help="payload RNG seed")
    ap.add_argument("--gate-size", type=int, default=GATE_SIZE_BYTES,
                    help=f"size bucket the p95 gate applies to (default {GATE_SIZE_BYTES})")
    ap.add_argument("--gate-ms", type=float, default=GATE_P95_MS,
                    help=f"p95 budget in ms for the gate size (default {GATE_P95_MS:g})")
    ap.add_argument("--keep-cache", action="store_true",
                    help="do not clear the clean-chunk cache between iterations")
    args = ap.parse_args()

    if args.iterations < 1:
        ap.error("--iterations must be >= 1")

    policy = copy.deepcopy(load_policy())
    policy.setdefault("detectors", {}).setdefault("llm", {})["enabled"] = False

    sizes = sorted(set(args.sizes))
    if args.gate_size not in sizes:
        sizes.append(args.gate_size)
        sizes.sort()

    print(f"sanitize latency benchmark  (iterations={args.iterations}, seed={args.seed}, "
          f"chunk cache {'kept' if args.keep_cache else 'cleared'} per run)")
    print(f"python {sys.version.split()[0]}  chunk threshold={engine.CHUNK_THRESHOLD}B  "
          f"chunk target={engine.CHUNK_TARGET}B")
    print()

    results: dict[int, dict] = {}
    for size in sizes:
        payload = generate_payload(size, seed=args.seed)
        print(f"  benchmarking {_size_label(size):>6} ...", end="", flush=True)
        times, n_spans = bench(payload, args.iterations, policy, clear_cache=not args.keep_cache)
        results[size] = {
            "p50": percentile(times, 50),
            "p95": percentile(times, 95),
            "p99": percentile(times, 99),
            "mean": statistics.fmean(times),
            "max": max(times),
            "spans": n_spans,
            "path": "single" if size <= engine.CHUNK_THRESHOLD else "chunked",
        }
        print(f" p95={results[size]['p95']:.1f}ms")

    _, detectors_run, _, _ = engine._get_analyzer(policy)
    print()
    print(f"detectors: {', '.join(detectors_run)}")
    print(f"gliner:    {_gliner_status(policy)}")
    print()

    hdr = f"{'size':>7} {'path':>8} {'spans':>6} {'p50 ms':>9} {'p95 ms':>9} {'p99 ms':>9} {'mean ms':>9} {'max ms':>9}"
    print(hdr)
    print("-" * len(hdr))
    for size in sizes:
        r = results[size]
        print(f"{_size_label(size):>7} {r['path']:>8} {r['spans']:>6} "
              f"{r['p50']:>9.1f} {r['p95']:>9.1f} {r['p99']:>9.1f} {r['mean']:>9.1f} {r['max']:>9.1f}")
    print()

    gate_p95 = results[args.gate_size]["p95"]
    label = _size_label(args.gate_size)
    if gate_p95 > args.gate_ms:
        print(f"FAIL: {label} p95 = {gate_p95:.1f}ms exceeds budget of {args.gate_ms:g}ms")
        return 1
    print(f"PASS: {label} p95 = {gate_p95:.1f}ms within budget of {args.gate_ms:g}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
