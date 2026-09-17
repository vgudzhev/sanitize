# Enterprise Readiness Assessment & Architecture Plan

**Status:** v1 — assessment of the tree at commit `16e9563` plus the uncommitted GLiNER2 changes
**Date:** 2026-09-16
**Audience:** implementing agent (Opus 4.6). Every task below names files, the change, and how it is verified. Work the phases in order; each phase ends with a green CI run and an updated rating in §1.

---

## 1. Rating: 4 / 10 for production enterprise use today

**What a 4 means:** the architecture is right and unusually well documented (threat model, ADRs, fail-closed everywhere, spans-not-text contract, egress backstop, 284 tests, 100 % recall on the synthetic secrets corpus). It is a strong prototype. It is not deployable to an enterprise yet because (a) the documented Claude Code integration does not exist and the only viable Claude Code path — the gateway — has protocol-level bugs, (b) detection *precision* has never been measured, so nobody knows whether it makes the agent unusable on real code, and (c) the service has no production operations story (blocking event loop, no limits, misleading health, models pulled from the internet at runtime, no release process).

Scorecard (0–10):

| Dimension | Score | One-line reason |
|---|---|---|
| Architecture & threat model | 8 | Correct trust boundaries, fail-closed, stateless detector, client-side vault, ADRs. Keep. |
| Secret recall (synthetic) | 7 | 317/317 on `evals/`, but the corpus is small, synthetic, all items < 4 KB, and never exercised with GLiNER in CI. |
| Precision / developer utility | 2 | Never measured. `evals/run_evals.py:56` declares `total_false_positives` and never uses it. |
| Claude Code integration | 2 | Docs describe a `~/.claude/extensions/` loader that Claude Code does not have. Gateway path works in principle but has the bugs in §3.2. |
| pi integration | 5 | Hooks are complete and tested against a fake `ExtensionAPI`; real-pi drift risk; one data-corruption bug (§3.3-1). |
| Gateway correctness | 3 | Streaming status codes, `input_json_delta`, end-of-stream flush, vault leak, base64 scanning. |
| Security engineering | 5 | Good primitives (AES-GCM, Ed25519 policy, tightening-only merge); weak key handling and shared static token. |
| Operations & observability | 3 | No Prometheus/OTel, no request limits, health reports GLiNER as running when it is not, CPU-bound work on the event loop. |
| Supply chain / offline / release | 2 | HF download at first request, unpinned deps, no SBOM/signing, version string in three places. |
| Test rigor | 5 | Good unit coverage; no end-to-end test against a real harness or a real Anthropic streaming exchange with tool calls. |
| Documentation | 5 | Excellent structure; currently states incorrect integration instructions. |

**Target:** 7/10 after Phases 0–3 (deployable to a pilot team with an SRE owner); 8/10 after Phases 4–5. 9+ requires months of field use — no plan can substitute for that.

---

## 2. What is already right (do not regress)

- Detection returns spans, never rewritten text (ADR-3). Merging is trivial and model layers cannot corrupt content.
- Fail closed at every boundary: `SanitizeUnavailableError` → `[[SCRUBBER_UNAVAILABLE]]`, egress abort, policy-signature failure withholds everything.
- Stateless detection service; vault never leaves the client (ADR-2). This is what makes org mode safe to share.
- Egress verifier is *independent* of the detection service (`extension/src/egress.ts`), so a service bug cannot disable the last line.
- LLM layer is additive-only, score-capped at 0.79, JSON-schema constrained (ADR-7).
- Signed central policy with canonical JSON + Ed25519, tightening-only local merge (`sanitize/sanitize/policy.py:98`).
- No content logging anywhere; metrics are category counts.
- Deny-list blocks before content exists (ADR-8).

---

## 3. Findings, ranked

Severity: **S1** = leaks or corrupts data / blocks adoption outright; **S2** = breaks in realistic use; **S3** = enterprise reviewers will reject; **S4** = hygiene.

### 3.1 Integration truth

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | S1 | Claude Code has no `~/.claude/extensions/` TypeScript loader. Its hooks cannot rewrite prompts (`UserPromptSubmit` can only block / add context) or tool results (`PostToolUse` fires after execution and cannot transform output). The extension in `extension/` is pi-only (`package.json` declares `"pi": {"extensions": [...]}` and a peer dep on `@earendil-works/pi-coding-agent`). The site, quickstart, usage guide and architecture §1 all claim otherwise. | `docs/architecture.md:24-33`, `docs/quickstart.md:58-62`, `docs/usage.md:26-30`, `docs/index.html:1054-1055`, `extension/src/config.ts` (`.claude` lookup) |
| 2 | S1 | The only viable Claude Code integration is `ANTHROPIC_BASE_URL` → the gateway (Claude Code honours it; it sends `x-claude-code-session-id`, SSE with pings, `input_json_delta`, `cache_control`, `/v1/messages/count_tokens`). This is documented as "any LLM client", not as *the* Claude Code path, and the gateway has never been tested against Claude Code's actual traffic. | `sanitize/sanitize/gateway.py` |
| 3 | S2 | Claude Code hooks *can* do two useful things: `PreToolUse` → `hookSpecificOutput.updatedInput` (deny-list + rewrite of tool input) and `SessionStart` (health check). Packaging as a Claude Code plugin (`.claude-plugin/plugin.json` with `hooks/hooks.json`) is supported and not used. | none yet |
| 4 | S3 | Documented constraints to verify empirically before promising: OAuth (claude.ai subscription) traffic may require a direct connection — API-key / `ANTHROPIC_AUTH_TOKEN` is the documented gateway path. Bedrock (SigV4 signs the body) cannot be proxied with body rewriting; Vertex uses a different URL shape. | docs |

### 3.2 Gateway (the Claude Code path)

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | S1 | Vault memory leak with plaintext secrets: a new session (and vault) is created per request when the client does not send `X-Sanitize-Session` (Claude Code does not). `_cleanup_sessions()` runs only from `/health`. | `gateway.py:278`, `gateway.py:82-87`, `gateway.py:264` |
| 2 | S1 | Streaming tool calls are corrupted: `input_json_delta.partial_json` fragments are rehydrated per event with no cross-fragment buffering and **no JSON escaping** of substituted values. A PEM key (`\n`) or any value with `"` / `\` produces invalid JSON in the client's reassembled tool input. | `gateway.py:222-230`, `gateway.py:380` |
| 3 | S1 | Upstream HTTP status is not propagated on streaming responses (`StreamingResponse` defaults to 200). A 401/429/529 from Anthropic becomes a 200 SSE stream; Claude Code's retry/backoff never triggers. | `gateway.py:386-390` |
| 4 | S2 | Anthropic streams end with `message_stop`, not `[DONE]`; `StreamRehydrator.flush()` is never called, so buffered trailing text is dropped. Buffer must also flush at `content_block_stop` (a placeholder cannot span blocks). | `gateway.py:355-364` |
| 5 | S2 | Every string in the body is scanned, including base64 `source.data` of image/document blocks (entropy layer will flag base64 runs → corrupts the image; also seconds of latency) and structural fields (`model`, `type`, `role`). | `gateway.py:123-131` |
| 6 | S2 | The full message history is re-detected on every request (`O(history)` per turn; GLiNER on CPU makes long sessions take seconds per turn). Only clean chunks > 4 KB are cached. | `gateway.py:108-120`, `engine.py:386-410` |
| 7 | S2 | No egress backstop in the gateway (the extension has one). No enforcement of loopback binding (docs only). Detection exceptions surface as 500 tracebacks. | `gateway.py` |
| 8 | S3 | `_PLACEHOLDER_RE = \[\[[A-Z_]+_\d+\]\]` cannot rehydrate custom pattern names containing digits (`CUSTOMER_ID2`). Same regex in `extension/src/vault.ts:45` and `engine.py:170`. | three places |
| 9 | S3 | ADR-5 ("session scrubbed at rest") does not hold in gateway mode: Claude Code stores the rehydrated response and raw tool results in its own transcript. Not a bug, but undocumented. | docs |

### 3.3 Extension (pi path)

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | S1 | One vault file for all sessions (`~/.sanitize/vault.enc`), overwritten on every shutdown. `/sanitize resume` in session A can load session B's mapping; `[[HOST_1]]` then rehydrates to the wrong host **inside tool arguments**. | `extension/src/index.ts:85`, `:438-447` |
| 2 | S2 | Egress raw-value check compares `JSON.stringify(payload)` against unescaped raw values; any value containing `"`, `\` or a newline (private keys) is invisible to the check. Regex checks still catch PEM headers. | `extension/src/index.ts:278-296` |
| 3 | S2 | Egress false positives are unrecoverable: `GENERIC_SECRET_ASSIGNMENT` runs over the whole payload including the system prompt and tool schemas; a hit aborts the request with no override path. | `extension/src/egress.ts:37-40` |
| 4 | S3 | pi API surface is hand-mirrored (`types.ts` "shapes confirmed from 0.85.1"), peer dep is `>=0.85.1` with no upper bound, tests run only against a fake API. A pi rename silently removes a layer. | `extension/src/types.ts:1-3`, `extension/package.json:26` |
| 5 | S3 | Vault passphrase from an env var (visible to `ps`), PBKDF2-SHA256 at 100 k iterations. Architecture promised OS keychain. | `extension/src/index.ts:86`, `vault-persistence.ts:9` |

### 3.4 Detection quality

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | S1 | Precision is not measured. No clean corpus, no per-detector FP rate, no gate. Symptom already observed: the v1 GLiNER model flags the literal word "password" as `PASSWORD` at 0.94 (`# set password=ok`). | `evals/run_evals.py` |
| 2 | S2 | For texts > 4096 chars the chunked path skips any chunk that does not match `_CHUNK_PREFILTER` (secrets patterns, emails, private IPs). A 10 KB CSV of names, phone numbers, card numbers and public IPs with no email in it is not scanned at all. All eval items are < 4 KB, so the gate cannot see this. | `engine.py:393`, `engine.py:194-208` |
| 3 | S2 | The chunk fast path bypasses spaCy, so Presidio recognizers without `patterns` (phone via `phonenumbers`, spaCy PERSON/LOCATION) never run on large outputs. | `engine.py:128-140`, `:258-307` |
| 4 | S2 | GLiNER v1 truncates input at 384 tokens (`Sentence of length 462 has been truncated to 384` in the test log). For ≤ 4 KB texts the whole text is sent in one call, so everything after ~1 500 chars is invisible to layer 4. The gliner2 path now uses `extract_entities_long` (windowed); the v1 path does not window. | `recognizers/gliner.py` |
| 5 | S2 | No NER categories in the corpus (no person, address, organization, hostname, codename). Layer 4 recall is unmeasured, and the CI eval job installs no GLiNER backend. | `evals/corpus/`, `.github/workflows/ci.yml:46-64` |
| 6 | S3 | `fastino/gliner2-privacy-filter-PII-multi` is the default but has not been executed in this repo (venv has only `gliner` v1). The backend code is unit-tested with mocks only. Threshold 0.5 is the model card default, not calibrated here. | `recognizers/gliner.py` |
| 7 | S3 | Org tightening rules protect `threshold` and `labels` but not `detectors.gliner.model`; a local config can swap in a weaker model. | `policy.py:93-94` |
| 8 | S4 | Clean-chunk cache stops caching at 4 096 entries instead of evicting. | `engine.py:212-213` |

### 3.5 Service operations (org mode)

| # | Sev | Finding | Where |
|---|---|---|---|
| 1 | S2 | `/v1/detect` is `async def` calling synchronous CPU-bound code (spaCy, GLiNER). One slow request blocks the event loop for every client, including `/v1/health`. | `app.py:121-130` |
| 2 | S2 | `/v1/health` lists `gliner` in `detectors` even when the model failed to load (`detectors_run.append("gliner")` is unconditional). Operators believe NER is on when it is silently off. | `engine.py:99-100`, `app.py:133-137` |
| 3 | S2 | Models are downloaded from Hugging Face on the first `analyze`. Enterprise networks without egress get a permanent, silent layer-4 outage; first-request latency is the model download. The container image ships no GLiNER at all. | `recognizers/gliner.py`, `Dockerfile` |
| 4 | S3 | No request body limit, no rate limit, no per-request timeout on detection. | `app.py` |
| 5 | S3 | Bearer token compared with `!=` (not constant-time); one shared static token for all developers; metrics are per-worker in-process dicts (`--workers 2` → inconsistent `/v1/metrics`). | `app.py:72-79`, `:108-119`, `Dockerfile:24` |
| 6 | S3 | No Prometheus endpoint, no structured logs, no request IDs, no traces. Policy is loaded once; no hot reload, no schema validation (`threshold: "high"` is accepted and explodes later). | `app.py`, `policy.py` |
| 7 | S4 | Version string duplicated (`app.py` ×2, `pyproject.toml`, docs); README test counts stale. | several |

---

## 4. Target architecture

Two harness paths, one detection engine, one policy model.

```
┌────────────────────────────── developer machine (trusted) ──────────────────────────────┐
│                                                                                          │
│  Claude Code ──ANTHROPIC_BASE_URL=http://127.0.0.1:7412/anthropic──► sanitize-gateway    │
│     │  plugin hooks:                                                  (loopback only)    │
│     │   PreToolUse   → deny-list block, tool-input rewrite            • vault keyed by  │
│     │   SessionStart → gateway health, warn/refuse if down              x-claude-code-  │
│     │   /sanitize    → status | show | test                             session-id      │
│     │                                                                 • scrub request   │
│  pi ──extension (unchanged design)──► vault in extension               (content-block   │
│         input / tool_result / tool_call / context / egress              cache)          │
│                                                                       • rehydrate text  │
│                                 ┌──────────────────────────────┐        + tool_use JSON │
│                                 │ detection engine             │◄───────┘ (stream-safe) │
│                                 │ in-process (personal) or     │                        │
│                                 │ remote /v1/detect (org)      │                        │
│                                 └──────────────────────────────┘                        │
└──────────────────────────────────────────┬───────────────────────────────────────────────┘
                                           │ placeholders only, egress-verified, fail closed
                                           ▼
                     api.anthropic.com / API-key LLM gateway (LiteLLM etc.) → Bedrock/Vertex
```

Rules that follow from this:

1. **Claude Code = gateway + plugin.** The gateway is the scrubber; the plugin adds the deny-list and UX. Never describe an "extension" for Claude Code again.
2. **The vault never leaves the developer machine** in either path. In org mode the *gateway* stays local and only detection is remote (`SANITIZE_URL`), exactly like the extension.
3. **One engine, one policy schema, one placeholder grammar** shared by gateway, extension and service. The placeholder regex lives in one place per language and accepts digits in type names.
4. **Detection is content-addressed per session.** A content block that was scrubbed once in a session is never re-detected; history cost is O(new content).
5. **Every model dependency is resolvable offline** (bundled in the image or pointed at an internal mirror) and every layer reports its true state in `/v1/health`.

---

## 5. Implementation phases

Conventions for the implementing agent:

- Task IDs are `P<phase>-<n>`. Do them in order inside a phase; phases are sequential.
- "Verify" lists the test or command that proves the task. Add the test in the same change.
- Keep the fail-closed invariant in every new branch: an error path must never emit raw content.
- Do not add comments that narrate the change; commit messages carry the why.
- Run `cd extension && npm test`, `cd sanitize && python -m pytest tests/ -q`, and `python evals/run_evals.py` before each phase's final commit.

### Phase 0 — Truth and safety (1–2 days)

Goal: nothing in the repo claims something false; no known data-corruption path remains.

| ID | Task | Files | Verify |
|---|---|---|---|
| P0-1 | Rewrite the Claude Code story as **gateway + plugin**. Remove every `~/.claude/extensions` instruction. Quickstart/usage/site "Claude Code" tab becomes: start gateway → `export ANTHROPIC_BASE_URL=http://127.0.0.1:7412/anthropic` → install plugin (P1-8). Architecture §1 becomes "Supported harnesses: pi (extension), Claude Code (gateway + plugin), any SDK (gateway)". Note the OAuth/Bedrock constraints from §3.1-4 as "verify on your setup". | `docs/architecture.md`, `docs/quickstart.md`, `docs/usage.md`, `docs/index.html`, `README.md` | `grep -rn "claude/extensions" docs README.md` returns nothing; site tab renders (open `docs/index.html`). |
| P0-2 | Keep `.claude/sanitize.yaml` as a config location (the plugin will read it) but make `config.ts` comments/docs say it is read by the plugin/gateway, not by an extension. | `extension/src/config.ts`, docs | existing `config.test.ts` still green. |
| P0-3 | Per-session vault files. Path `~/.sanitize/vaults/<sessionId>.enc`; store `sessionId` inside the encrypted JSON; `restoreFrom` refuses a blob whose `sessionId` differs. Derive `sessionId` from pi's session (`ctx.sessionId` if exposed by `@earendil-works/pi-coding-agent` ≥ 0.85.1, else sha256 of the session file path). Delete legacy `vault.enc` on first run. | `extension/src/index.ts`, `vault-persistence.ts`, `vault.ts`, `ui.ts` | New tests in `vault-persistence.test.ts`: cross-session restore is rejected; same-session restore round-trips. |
| P0-4 | Gateway session hygiene: key the vault by `x-claude-code-session-id`, then `X-Sanitize-Session`, else a hash of `metadata.user_id` + first user message, else per-request; run `_cleanup_sessions()` on every request; cap sessions at `SANITIZE_GATEWAY_MAX_SESSIONS` (default 64, LRU evict); zero vault dicts on eviction. | `sanitize/sanitize/gateway.py` | `test_gateway.py`: two requests with the same `x-claude-code-session-id` share placeholders; 100 header-less requests leave ≤ 64 sessions. |
| P0-5 | Honest health: `detectors_run` includes `gliner` only after `_ensure_model()` succeeded; add `"degraded": [...]` listing layers that failed to load and a `warm` flag. `/v1/health` returns 503 when `SANITIZE_REQUIRE_GLINER=1` and GLiNER is unavailable. Warm the model at startup (lifespan) instead of on first request. | `engine.py`, `app.py`, `recognizers/gliner.py` | `test_api.py`: health reports `degraded: ["gliner"]` when the backend import is patched out; startup warm-up test. |
| P0-6 | Protect `detectors.gliner.model` in `_tighten_merge` (central wins); validate policy with a pydantic model (types, ranges, unknown keys → warning). | `policy.py` | `test_policy_org.py`: local model override ignored; `threshold: "high"` raises at load with a clear message. |
| P0-7 | Fix README drift: test counts, threshold, install lines, "via the pi agent harness" → both harnesses. Single source for the version: read it from `importlib.metadata` in `app.py`. | `README.md`, `app.py`, `pyproject.toml` | `grep -n "0.2.0" sanitize/sanitize/app.py` returns nothing. |

**Definition of done:** docs contain no false integration claims; CI green; §1 rating updated to 5.

### Phase 1 — Claude Code path: gateway correctness + plugin (1–2 weeks)

Goal: Claude Code on a real project runs for an hour through the gateway with tool calls, images and long outputs, with no protocol errors and no raw secret in any upstream request.

| ID | Task | Files | Verify |
|---|---|---|---|
| P1-1 | Propagate upstream status and headers on streaming: open the upstream stream first, then build `StreamingResponse(status_code=upstream.status_code, ...)`. Non-2xx upstream bodies are passed through unmodified (they contain no placeholders). Map httpx connect/read errors to a JSON 502 `{"type":"error","error":{"type":"sanitize_upstream_error"}}`. | `gateway.py` | `test_gateway.py`: fake upstream returns 429 with `retry-after` → client sees 429 + header; connection refused → 502 JSON. |
| P1-2 | Anthropic stream state machine: track `content_block_start/stop`; one `StreamRehydrator` per text block; a `JsonStringRehydrator` per `tool_use` block that buffers `partial_json`, rehydrates, and JSON-escapes substituted values (`json.dumps(v)[1:-1]`); flush both on `content_block_stop` and `message_stop`; pass `ping`, `message_delta`, `error` events through untouched and immediately (Claude Code's 300 s event watchdog). | `gateway.py` | Fixture-driven tests replaying a real Claude Code SSE exchange (record with `SANITIZE_GATEWAY_RECORD=1` against a scrub-safe prompt, or hand-write from the Messages API spec): PEM value inside a `tool_use` input arrives as valid JSON with `\n`; placeholder split across three `partial_json` events; trailing placeholder in the last `text_delta`. |
| P1-3 | Scrub only content: walk `messages[].content[]` text blocks, `tool_result` content, `tool_use.input` strings, `system` (string or blocks), `tools[].description`; skip `type: image|document` `source.data`, `model`, `role`, `type`, `cache_control`, `metadata`, `stop_sequences`. Keep `cache_control` markers attached to the same blocks after scrubbing. | `gateway.py` | Test: a 2 MB base64 image block is byte-identical after scrubbing and detection is not invoked on it. |
| P1-4 | Content-block cache: per session, `sha256(text) → scrubbed text` after substitution (not just "clean"). On each request only blocks with unseen hashes hit the engine. Bound the cache per session (e.g. 4 096 entries, LRU). Because the same vault is used, output is byte-stable across turns, which preserves prompt caching. | `gateway.py` | Test: second request with the same history calls `engine.detect` only for the new block; scrubbed bytes of the shared prefix are identical. |
| P1-5 | Gateway egress backstop + fail-closed semantics: port `egress.ts` checks to Python (`sanitize/sanitize/egress.py`, shared by gateway and, later, `/v1/verify`); run over the serialized upstream body; on hit return 422 `sanitize_egress_blocked` with the category, never forward. Any detection exception → 503 `sanitize_unavailable`, never forward raw. | `gateway.py`, new `egress.py` | Tests for both codes; extension `egress.test.ts` fixtures reused as Python parametrized cases so the two verifiers cannot drift. |
| P1-6 | Loopback enforcement and remote detection: refuse to start unless the bound host is loopback or `SANITIZE_GATEWAY_ALLOW_NON_LOOPBACK=1`; when `SANITIZE_URL` is set, call the remote `/v1/detect` (bearer token, timeout, fail closed) instead of the in-process engine so org mode works for Claude Code without moving the vault. | `gateway.py`, new `sanitize/sanitize/detect_client.py` | Tests: non-loopback bind aborts; remote 500/timeout → 503 to the client. |
| P1-7 | Placeholder grammar in one place: `[[<TYPE>_<n>]]` with `TYPE = [A-Z][A-Z0-9_]*`; export from `engine.py` and `extension/src/format.ts`; custom pattern names validated against it at policy load. | `engine.py`, `gateway.py`, `extension/src/vault.ts`, `format.ts`, `policy.py` | Round-trip test with type `CUSTOMER_ID2` in both languages. |
| P1-8 | Claude Code plugin `claude-plugin/` at repo root: `.claude-plugin/plugin.json`; `hooks/hooks.json` with `PreToolUse` (matcher `Read|Edit|Write|Bash`) running `bin/sanitize-hook` (Node, reuses `denylist.ts` + `config.ts`) that returns `permissionDecision: "deny"` for deny-listed paths; `SessionStart` hook that checks `GET http://127.0.0.1:7412/health` and prints a warning banner if the gateway is down or `ANTHROPIC_BASE_URL` is not set; `commands/sanitize.md` for `/sanitize status|show|test` (talks to a new gateway `GET /session/<id>/placeholders` that returns types only, loopback-only). Document install via a local marketplace path. | new `claude-plugin/`, `extension/src/denylist.ts` (shared), docs | `claude-plugin/tests/hook.test.ts` feeding hook JSON on stdin; manual check: `claude --plugin-dir ./claude-plugin` blocks `cat ~/.ssh/id_rsa`. |
| P1-9 | End-to-end harness: `evals/e2e_gateway.py` starts the gateway against a fake Anthropic upstream (records every request body), drives a scripted conversation containing an AWS key pair, a DB URL, a PEM block and a 60 KB log tail, asserts zero raw values in any recorded upstream body, valid JSON in every reassembled `tool_use`, and byte-identical scrubbed prefixes across turns. Run in CI. | new `evals/e2e_gateway.py`, `ci.yml` | CI job `gateway-e2e` green. |
| P1-10 | Document gateway-mode trust differences: transcript at rest contains real values (ADR-5 exception); optional `SANITIZE_GATEWAY_REHYDRATE_TEXT=0` keeps placeholders in assistant text for stricter at-rest posture. Add ADR-9 "Claude Code via gateway". | `docs/threat-model.md`, `docs/decisions/ADR-9-*.md`, `docs/usage.md` | Review. |

**Definition of done:** P1-9 passes in CI; a human runs Claude Code through the gateway for a real session (tool calls, `Read` of a large file, an image paste) with no errors. Rating → 6.

### Phase 2 — Detection quality you can prove (1–2 weeks)

Goal: recall *and* precision are measured per detector on inputs shaped like real coding sessions, and both are CI gates.

| ID | Task | Files | Verify |
|---|---|---|---|
| P2-1 | Clean corpus: `evals/corpus_clean/` — ≥ 200 real-shaped samples with zero secrets (source files in 6 languages, package lockfiles, stack traces, `git log`, Dockerfiles, YAML/JSON configs with dummy values, CSVs of product data, English prose). Generated deterministically by `generate_corpus.py`; the "password" word in identifiers (`password_hash`, `getPassword`) must appear. | `evals/` | Runner reports FP count per detector and per category. |
| P2-2 | Precision gate: extend `run_evals.py` to compute per-detector precision on the mixed corpus and FP rate on the clean corpus; gate: deterministic layers ≤ 0.5 FP per 10 KB, GLiNER ≤ 2 per 10 KB (tune after first measurement, then freeze). Print the top-10 FP strings so they can be triaged. | `evals/run_evals.py` | CI fails on regression. |
| P2-3 | NER corpus: categories `person_name`, `street_address`, `organization`, `internal_hostname`, `project_codename`, `unstructured_credential` ("the password is …"), each ≥ 15 items, in log/code/prose contexts. Gate: ≥ 90 % recall with the gliner2 backend. | `evals/corpus/`, `generate_corpus.py` | Runner table shows the new rows. |
| P2-4 | Large-output recall: add ≥ 20 items > 4 KB (CSV of names/phones/cards with no email; a 30 KB log with one hostname and one IP; a 50 KB JSON with one nested secret) and fix the chunked path: run Presidio pattern recognizers on *every* chunk (cheap), use the prefilter only to skip GLiNER/spaCy, and run GLiNER on chunks that contain letters (not on base64/hex runs). Add `hints.source`-aware gating (`tool_result` ≥ N bytes → GLiNER windowed with `extract_entities_long`; `input` → always). | `engine.py`, `recognizers/gliner.py` | New eval rows pass; `bench_latency.py` p95 for 50 KB ≤ 300 ms without GLiNER, ≤ 2 s with GLiNER on the reference laptop (record numbers in `docs/benchmarks.md`). |
| P2-5 | GLiNER v1 windowing: when the backend is `gliner`, split text into ≤ 300-token windows with 32-token overlap and merge spans (the gliner2 path already windows). | `recognizers/gliner.py` | Test: a person name at char 3 000 of a 3 500-char text is found with a mocked model that asserts every call ≤ 384 tokens. |
| P2-6 | Actually run the default model: install `gliner2[local]` in CI's eval job (cache the HF download), calibrate the threshold on the mixed corpus (report recall/precision at 0.3/0.4/0.5/0.6), pin the model revision (`revision=` commit hash in `from_pretrained`), and record the choice in `docs/decisions/open-questions.md` Q4. | `ci.yml`, `recognizers/gliner.py`, docs | Eval job output includes the gliner2 backend name. |
| P2-7 | Per-layer timing in `stats` (`{"ms": {"gitleaks": 1, "presidio": 5, "gliner": 40}}`) and a `detectors_skipped` list with reasons; surface in `/sanitize status`. | `engine.py`, `app.py`, `extension/src/ui.ts` | Test asserts keys exist. |
| P2-8 | Egress false-positive escape hatch (extension and gateway): `allow_egress` list of literal strings in `sanitize.yaml` (add-only in org mode), and a `/sanitize allow-once <category>` command that permits the next request; both logged as audit events. Never a global off switch. | `egress.ts`, `egress.py`, `config.ts`, `ui.ts`, `policy.py` | Tests: allow-once permits exactly one request. |

**Definition of done:** precision and recall tables in `docs/benchmarks.md`, gates in CI, GLiNER2 measured. Rating → 7 (with Phase 3).

### Phase 3 — Service hardening for org mode (1–2 weeks)

Goal: `sanitize` runs as a shared service that an SRE can operate: bounded, observable, offline-capable, honest.

| ID | Task | Files | Verify |
|---|---|---|---|
| P3-1 | Move CPU work off the event loop: `def detect` (threadpool) with `anyio.to_thread` **or** a `ProcessPoolExecutor` sized to CPU count for GLiNER; make `_analyzer_cache`, `_CLEAN_CHUNK_CACHE` and model access thread-safe (lock or per-worker instances). | `app.py`, `engine.py` | Load test (`evals/bench_latency.py --concurrency 8`): `/v1/health` p99 < 50 ms while 8 detect requests of 50 KB run. |
| P3-2 | Limits: `SANITIZE_MAX_BODY_BYTES` (default 2 MiB → 413), per-request detection deadline (default 8 s → 503, fail closed), optional token-bucket rate limit per bearer identity. | `app.py` | Tests for 413 and 503. |
| P3-3 | Auth: `hmac.compare_digest`; support multiple tokens (`SANITIZE_TOKENS=name:token,...`) so each team/CI has its own and revocation is possible; accept identity from a trusted proxy header (`X-Forwarded-User`, only when `SANITIZE_TRUST_PROXY=1`) for per-user metrics; document OIDC/mTLS at the proxy as the recommended production auth. | `app.py`, docs | Tests: wrong token 403, revoked token 403, identity label appears in metrics. |
| P3-4 | Observability: Prometheus `/metrics` (requests, spans by category, latency histogram per layer, degraded-layer gauge), structured JSON logs with request IDs and **no text field ever**, optional OpenTelemetry traces (`SANITIZE_OTEL_ENDPOINT`). Keep `/v1/metrics` for the extension. | `app.py`, new `telemetry.py` | Test asserts no log record contains request text (extend `test_gateway_does_not_log_secrets` to the service). |
| P3-5 | Readiness vs liveness: `/v1/health/live` (process up) and `/v1/health/ready` (policy loaded, spaCy loaded, required layers warm). Docker `HEALTHCHECK` uses ready. | `app.py`, `Dockerfile` | Compose smoke test. |
| P3-6 | Offline models: `Dockerfile` target `sanitize:full` that pre-downloads spaCy + gliner2 weights at build time into `/models` and sets `HF_HUB_OFFLINE=1`; `SANITIZE_MODEL_DIR` for air-gapped installs; document the internal-mirror option. | `Dockerfile`, `recognizers/gliner.py`, docs | Container starts with networking disabled and `/v1/health/ready` reports `gliner` warm. |
| P3-7 | Policy lifecycle: hot reload on SIGHUP and on signed-policy file change; `policy_version` derived from content hash (drop the date prefix so it is stable); `/v1/policy` returns the schema version; reject unknown schema versions. | `app.py`, `policy.py` | Test: reload changes version without restart. |
| P3-8 | Extension/gateway org client: `policy_url` polling interval with signature re-verification; cache the last good signed policy on disk; refuse to run with an expired policy (`expires_at` in the signed blob). | `extension/src/client.ts`, `index.ts`, `scripts/sign-policy.py` | Tests: expired policy → withheld. |

**Definition of done:** a `docker compose` example with nginx + OIDC stub + two sanitize replicas passes P1-9 through the shared service; runbook in `docs/operations.md`. Rating → 7.

### Phase 4 — Supply chain and release (3–5 days)

| ID | Task | Files | Verify |
|---|---|---|---|
| P4-1 | Pin and lock: `uv.lock`/`requirements.lock` for the service with hashes; `npm ci` already; Renovate/Dependabot config; pin GitHub Actions by SHA. | `sanitize/`, `.github/` | CI uses the lock. |
| P4-2 | Model provenance: record model repo + revision + sha256 of weights in `docs/models.md`; verify the hash at load when `SANITIZE_VERIFY_MODELS=1`. | `recognizers/gliner.py`, docs | Test with a tampered file → refuses. |
| P4-3 | Release pipeline: semver tags, `CHANGELOG.md`, container images built on tag, signed with cosign, SBOM (syft) attached, Trivy scan gate, `pip-audit`/`npm audit` gate. | `.github/workflows/release.yml` | A `v0.3.0` tag produces a signed image and SBOM. |
| P4-4 | Harness compatibility gate: CI job installs the pinned pi version, loads the extension for real, drives one scripted session (pi headless/RPC mode) and asserts the hook names still exist and fire; pin `peerDependencies` to a tested range (`>=0.85.1 <0.90`) and bump deliberately. Same for the Claude Code plugin: `claude -p` smoke run with the plugin dir and a deny-listed read. | `.github/workflows/ci.yml`, `extension/package.json` | Job green; failure message names the missing hook. |
| P4-5 | Vault key management: macOS Keychain / Linux Secret Service / Windows Credential Manager via a small native-free helper (`security` CLI on macOS, `secret-tool` on Linux) with the env var as fallback; Argon2id (or PBKDF2 ≥ 600 k) for the fallback path; document the trust model. | `extension/src/vault-persistence.ts`, new `keychain.ts` | Tests with the helper mocked; manual check on macOS. |

**Definition of done:** a tagged release an enterprise can pull, verify, and audit. Rating → 8 with Phase 5.

### Phase 5 — Enterprise features (ongoing)

| ID | Task | Notes |
|---|---|---|
| P5-1 | Audit sink contract: JSON schema for events, retention guidance, example SIEM forwarders (Splunk HEC, OpenSearch), per-event `session_id_hash` and `policy_version`; never content. |
| P5-2 | Per-team policies: `/v1/policy?team=` resolved from the proxy identity header; signed bundle per team; extension/gateway send the team claim. |
| P5-3 | Format-preserving placeholders (already prototyped) validated against parsers the model relies on (IPs, emails, URLs) with collision guarantees documented. |
| P5-4 | DLP interop: optional `webhook` detector layer calling an enterprise DLP API as an *untrusted additive* recognizer (same rules as the LLM layer). |
| P5-5 | Data residency & privacy docs: DPIA template, what crosses the boundary in org mode (text for detection, no retention), how to prove no-logging (config + audit). |
| P5-6 | pi `read` tool override (open question Q5) so the deny-list is enforced at the tool level, not only by argument heuristics. |

---

## 6. Highest-leverage changes if only one week is available

1. P0-1 + P0-4 + P1-1 + P1-2 — make the Claude Code path honest and correct.
2. P0-3 — per-session vault files (data-corruption bug).
3. P2-1 + P2-2 — measure precision before anyone judges the tool on a real repo.
4. P2-4 — PII recall on large outputs.
5. P0-5 + P3-6 — honest health and offline models, or layer 4 will be silently off in every enterprise network.

---

## 7. Things to verify empirically (do not assume)

| Question | How |
|---|---|
| Does a claude.ai-subscription (OAuth) Claude Code session send traffic through `ANTHROPIC_BASE_URL`? Docs say gateways need API-key/`ANTHROPIC_AUTH_TOKEN`. | Try it; if not, document "API key or console/enterprise auth required". |
| Does Claude Code send `x-claude-code-session-id` on every request including `count_tokens` and subagents? | Log header names (never bodies) in the gateway for one session. |
| Does Claude Code tolerate an SSE proxy that withholds a text delta for up to 64 chars? | Covered by P1-9; watch for the 300 s event watchdog on long thinking. |
| Real p95 of `gliner2-privacy-filter-PII-multi` on the reference laptop (Intel MacBook Pro 2019) per 2 KB chunk. | `evals/bench_latency.py --gliner`; record in `docs/benchmarks.md`. |
| pi hook coverage of compaction requests (Q1) against the pinned pi version. | P4-4 harness job with a forced compaction. |

---

## 8. Rating trajectory

| After | Expected rating | Why |
|---|---|---|
| Phase 0 | 5 | Nothing false, no known corruption path. |
| Phase 1 | 6 | Claude Code works through the gateway with proof. |
| Phase 2 + 3 | 7 | Quality measured, service operable, offline-capable. |
| Phase 4 + 5 | 8 | Auditable releases, team policies, compatibility gates. |
| 6+ months of pilot use | 9 | Field-validated precision, incident history, runbooks exercised. |
