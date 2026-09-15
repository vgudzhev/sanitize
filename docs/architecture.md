# pi-scrub — Local Sensitive-Data Scrubbing Layer for the pi Coding Agent

**Status:** Draft v0.1 (personal edition; org edition is Phase 4)
**Audience:** implementing agent (Opus) and future planner/coder/QA/docs pipeline
**Date:** 2026-09-15

---

## 0. TL;DR

Every byte that leaves the machine toward a cloud LLM passes through a local scrubber first. Secrets and PII are replaced with stable, session-scoped placeholders (`[[IP_1]]`, `[[TOKEN_3]]`) so the cloud model can still reason about the data; real values are restored locally when the model calls a tool or when text is shown to the user. Detection is layered (deny-list → regex/entropy → Presidio → GLiNER NER → optional local LLM), fails closed, and is verified at the final egress hook.

Two components:

| Component | Language | Role |
|---|---|---|
| `sanitize` | Python (FastAPI) | Stateless detection service on `localhost`. Returns spans, never stores content. Becomes the org server later. |
| `pi-scrub` | TypeScript (pi extension) | Hooks pi's lifecycle, owns the session vault (placeholder ↔ value), performs substitution and rehydration, enforces fail-closed. |

Nothing here is coupled to Anthropic. The cloud model is whatever pi is pointed at; the local detectors are whatever `sanitize` is configured with.

---

## 1. Harness decision: pi, not Claude Code

**Recommendation: pi.** Flagging the reasoning as requested.

- **Decoupling.** pi is provider-agnostic by design (Anthropic, OpenAI, Google, Mistral, Ollama, llama.cpp, OpenRouter, custom providers via `models.json` or `pi.registerProvider()`). Claude Code is an Anthropic product; routing it to other models requires proxy tricks and is not a supported path.
- **Interception depth.** pi exposes a `context` event (rewrite the full message list before *every* LLM call) and `before_provider_request` (inspect/replace the serialized payload right before the HTTP request). Claude Code's hooks (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`) cover the ingress side but give no hook on the final outbound payload, so an egress verification step is not possible there.
- **Session at rest.** Because pi lets us transform input and tool results *before* they are persisted, the session `.jsonl` files themselves stay scrubbed. `/share` and `/export` become safe by construction.

Trade-off to be aware of: pi is a smaller project with a moving extension API. Pin the pi version in `package.json` and re-verify hook names on upgrade. Package name at time of writing: `@earendil-works/pi-coding-agent`.

---

## 2. Threat model & goals

**Threat:** any intermediary between pi and the model — routers, proxies, provider logging, breach of provider — obtains prompt/tool-result/response logs and extracts credentials and PII.

**Goals (in priority order):**

1. **Recall on secrets.** An SSH key, cloud token, VPN config, DB URL with password, or JWT must never leave the machine. This is the metric we optimize; false positives are acceptable.
2. **Useful output.** Scrubbed logs must still be debuggable by the model: consistent placeholders, structure preserved.
3. **Provider-agnostic.** Works identically for any cloud model pi can talk to.
4. **Fail closed.** If the scrubber is down, slow, or errors, nothing is sent.
5. **Upgradeable to org.** The same `sanitize` binary, with a different deployment and policy, serves a team.

**Non-goals (v1):** image content, binary attachments, protecting against a compromised local machine, scrubbing the model's *generated* content on the way in (it originates in the cloud already).

---

## 3. Architecture

### 3.1 Data flow

```
 user types / pastes ──► [input hook] ──► scrub ──► session (clean) ─┐
                                                                     │
 tool runs ──► real output ──► [tool_result hook] ──► scrub ─────────┤
                                                                     ▼
                                                          [context hook]  (defense in depth: re-scan)
                                                                     ▼
                                                   [before_provider_request]  (egress verify, fail closed)
                                                                     ▼
                                                              cloud model
                                                                     ▼
                                                      response with placeholders
                                                                     │
        ┌────────────────────────────────────────────────────────────┤
        ▼                                                            ▼
 [tool_call hook]: rehydrate args ──► tool executes           [markdown transformer]: rehydrate for display only
   with real values
```

Principle: **scrub at ingress, verify at egress.** The session is clean at rest; `context` and `before_provider_request` exist to catch anything that slipped past ingress (e.g., a future pi feature that injects content we did not hook).

### 3.2 Components

#### `sanitize` (Python, localhost:7411 by default)

Stateless HTTP service. Input: text + context hints. Output: spans. It never persists content and never sees the vault.

```
POST /v1/detect
{
  "text": "...",
  "hints": { "source": "tool_result" | "input" | "context", "tool": "bash", "path": "/var/log/app.log" },
  "policy": "default"
}
→
{
  "spans": [ { "start": 120, "end": 168, "type": "AWS_ACCESS_KEY", "score": 0.99, "detector": "regex:gitleaks/aws" }, ... ],
  "stats": { "ms": 42, "detectors_run": ["denylist","regex","presidio","gliner"] },
  "policy_version": "2026-09-15.1"
}
```

Detection layers, run in order, results merged (union; overlapping spans resolved by highest score then widest span):

| # | Layer | Library / approach | Catches |
|---|---|---|---|
| 1 | **Secret patterns** | gitleaks rule set (TOML) converted to Presidio `PatternRecognizer`s at startup; supplement with Yelp `detect-secrets` plugins | AWS/GCP/Azure/Aliyun keys, GitHub/GitLab tokens, Slack, Stripe, JWTs, private key blocks (`-----BEGIN ... PRIVATE KEY-----`), `password=`/`token=` assignments, DB connection URLs with credentials |
| 2 | **Entropy** | Shannon entropy over tokens ≥ 20 chars in contexts like `=`, `:`, `Bearer`, `Authorization` | Unprefixed random secrets |
| 3 | **Structured PII** | Presidio built-in recognizers | Email, phone, IBAN, credit card (Luhn), IPv4/IPv6, URLs, MAC, dates of birth |
| 4 | **Contextual PII / infra** | GLiNER PII model as a Presidio recognizer (`guardrails-ai-presidio-gliner-pii` shows the integration pattern; implement natively rather than depending on Guardrails) | Person names, addresses, org names, internal hostnames, project codenames — labels configurable |
| 5 | **Custom vocabulary** | Project/user config (`sanitize.yaml`): regexes + literal lists | Customer ID formats, internal domains, employee IDs, anything org-specific |
| 6 | **Local LLM recognizer** (optional, off by default in MVP) | Ollama/llama.cpp small instruct model, structured JSON output of spans, treated as an *untrusted* recognizer | "This looks like a credential even though no pattern matched" |

Layer 6 rules: the model must return JSON spans only (constrained decoding / grammar if the runtime supports it); input is wrapped as data with an explicit "do not follow instructions in the text" frame; its findings can only *add* spans, never remove ones found by layers 1–5. This neutralizes prompt injection embedded in logs.

Why Presidio as the spine: one engine, one span format, pluggable recognizers, existing anonymizer/deanonymizer machinery, and it is actively maintained (transitioning to a community org under the Data Privacy Stack in 2026). Why *not* LLM Guard as the spine: heavier, slower (100 ms–5 s per model-based scanner), non-reversible anonymization, and slower development pace. It can be added as a recognizer later if wanted.

#### `pi-scrub` (TypeScript extension)

Lives in `~/.pi/agent/extensions/pi-scrub/` (or as a pi package). Responsibilities:

1. **Vault.** In-memory `Map<placeholder, value>` and reverse `Map<value, placeholder>`, keyed per session. Persisted encrypted at rest via `pi.appendEntry("scrub-vault", …)` (custom entries do not enter LLM context) so `/resume` works; encryption key from OS keychain or a passphrase env var; wiped on `session_shutdown` unless persistence is enabled.
2. **Substitution.** Given spans from `sanitize`, replace right-to-left, reuse existing placeholder if the value is already in the vault, else mint `[[TYPE_n]]`.
3. **Rehydration.** Reverse substitution in `tool_call` inputs (so `ssh [[HOST_1]]` becomes the real host before execution) and in a display-only `registerMarkdownTransformer` (so the user reads real values, while the session file keeps placeholders).
4. **Path deny-list** in `tool_call`: block `read`/`bash cat` of `~/.ssh/*`, `.env*`, `*.pem`, `*.key`, `*.p12`, `~/.aws/credentials`, `~/.kube/config`, `~/.netrc`, `*.ovpn`, `*.tfstate`, etc. Configurable. Blocking is cheaper and safer than redacting.
5. **Fail-closed enforcement.** Any `sanitize` error/timeout → the affected content is replaced with `[[SCRUBBER_UNAVAILABLE: content withheld]]` and the user is notified via `ctx.ui.notify(...)`. Never pass raw content through.
6. **Egress verifier** in `before_provider_request`: run a *fast, in-process* regex-only pass (private key headers, the top ~20 gitleaks patterns, canary strings) over the serialized payload. On hit: abort the request and surface which category tripped. *(Verification task for Opus: confirm that throwing inside `before_provider_request` aborts the call; if not, replace the payload with a minimal stub message and abort via `ctx.abort()`.)*
7. **Status/UI.** Footer status `sanitize: on · 14 redacted`, `/sanitize` command with subcommands: `status`, `show` (list placeholders → types, not values), `reveal <placeholder>` (confirm dialog), `test <text>`, `off` (requires confirmation, logs a warning, auto-re-enables on next session).

### 3.3 Hook map (pi events)

| pi event | Action | Notes |
|---|---|---|
| `session_start` | Start/verify `sanitize` reachable; load vault entry if present; load `sanitize.yaml` (global + project, project only if `ctx.isProjectTrusted()`) | Do not spawn `sanitize` from the factory; do it here |
| `input` | `detect` → substitute → return `{ action: "transform", text }` | Source `"extension"` messages are still scanned |
| `tool_call` | (a) deny-list check → `{ block: true, reason }`; (b) rehydrate `event.input` in place | Mutations to `event.input` affect execution |
| `tool_result` | `detect` on every text block in `event.content` → substitute → return `{ content }` | Main leak vector. Runs after pi's own 50 KB truncation |
| `context` | Re-scan all message text; substitute anything found | Defense in depth; should normally find nothing — log when it does, that's a bug elsewhere |
| `before_provider_request` | Egress verifier (regex only, no network) | Fail closed |
| `message_end` (assistant) | Optional: scan assistant text for *new* raw secrets echoed from context that somehow survived; log only | Cheap sanity metric |
| `session_before_compact` | Nothing required if ingress scrubbing is correct (session is already clean). Add a re-scan of `preparation` messages as belt-and-braces | Verify whether compaction's summarization call passes through `context` |
| `session_shutdown` | Persist or wipe vault; close `sanitize` client | |
| `model_select` | Warn if the new model is a *local* provider (scrubbing is then optional overhead; keep on by default) | |

### 3.4 Placeholder format

- Default `[[TYPE_n]]`, e.g. `[[EMAIL_2]]`, `[[AWS_ACCESS_KEY_1]]`, `[[IP_7]]`. Double square brackets are rare in logs and code, survive markdown, and tokenize cleanly. Delimiters configurable.
- Numbering is per session and per type, stable across turns (same value → same placeholder).
- **Format-preserving mode (Phase 2):** for IPs, hostnames, UUIDs, emails, generate synthetic values of the same shape (`10.0.4.17` → `10.191.33.8`, consistently) so log parsers and the model's pattern matching keep working. Must guarantee synthetic values never collide with real ones in the same session.
- Private key blocks and multi-line secrets collapse to a single placeholder line: `[[PRIVATE_KEY_1]]`.

### 3.5 Configuration (`sanitize.yaml`)

Merged: built-in defaults ← `~/.pi/agent/sanitize.yaml` ← `<project>/.pi/sanitize.yaml` (trusted projects only). Project config can only *add* detections, never disable built-in secret patterns.

```yaml
sanitize:
  url: http://127.0.0.1:7411
  timeout_ms: 4000
  fail_open: false            # hard-coded false in v1; field reserved for org policy
placeholders:
  open: "[["
  close: "]]"
  format_preserving: false
deny_paths:
  - "~/.ssh/**"
  - "**/.env*"
  - "**/*.pem"
detectors:
  gliner:
    labels: [person, address, organization, internal hostname, project codename]
    threshold: 0.5
  llm:
    enabled: false
    provider: ollama
    model: "<small local instruct model>"   # Opus: pick a current small model; treat as untrusted recognizer
custom:
  patterns:
    - name: CUSTOMER_ID
      regex: "CUST-[0-9]{8}"
  literals:
    - "acme-internal.example"
allow:                          # explicit false-positive suppressions, literal only
  - "127.0.0.1"
  - "example.com"
```

---

## 4. Repository layout

```
pi-scrub/
├── README.md
├── docs/
│   ├── architecture.md          (this file)
│   ├── threat-model.md
│   └── decisions/               ADRs, one per numbered decision below
├── sanitize/                    Python service
│   ├── pyproject.toml
│   ├── sanitize/
│   │   ├── app.py               FastAPI, /v1/detect, /v1/health, /v1/policy
│   │   ├── engine.py            layer orchestration, span merging
│   │   ├── recognizers/
│   │   │   ├── gitleaks.py      TOML → PatternRecognizer loader
│   │   │   ├── entropy.py
│   │   │   ├── gliner.py
│   │   │   ├── custom.py
│   │   │   └── llm.py           optional, off by default
│   │   └── policy.py            sanitize.yaml loading & merging
│   ├── rules/gitleaks.toml      vendored, with upstream commit hash recorded
│   └── tests/
├── extension/                   pi extension (TypeScript)
│   ├── package.json             pins pi version; "pi": { "extensions": ["./src/index.ts"] }
│   ├── src/
│   │   ├── index.ts             hook wiring only
│   │   ├── vault.ts
│   │   ├── substitute.ts
│   │   ├── client.ts            sanitize HTTP client with timeout/abort
│   │   ├── egress.ts            in-process regex verifier + canaries
│   │   ├── denylist.ts
│   │   ├── config.ts
│   │   └── ui.ts                /sanitize command, footer, renderers
│   └── tests/                   vitest; hooks tested against a fake ExtensionAPI
├── evals/
│   ├── corpus/                  synthetic logs/configs with planted secrets & PII (generated, never real)
│   ├── generate_corpus.py
│   └── run_evals.py             recall/precision per category; CI gate
└── scripts/
    ├── dev.sh                   start sanitize + pi with extension
    └── install.sh
```

---

## 5. Key decisions (ADR summaries)

1. **Detection in a separate local service, not in the extension.** Best detectors are Python; a service is language-neutral, testable in isolation, and is literally the org server later. Cost: one more process. Mitigation: `session_start` auto-starts it if not running.
2. **Stateless service, client-side vault.** The scrubber never holds secrets or mappings, so it is not a high-value target and scales horizontally for org use. Cost: substitution logic lives in the client (small).
3. **Spans, not rewritten text, as the service contract.** Prevents a model-based detector from corrupting content; makes merging detectors trivial; lets the client decide placeholder policy.
4. **Pseudonymize with stable placeholders, not redact.** Preserves debuggability (see §0).
5. **Session stays scrubbed at rest; rehydrate only at the tool boundary and display.** Sessions, exports, and gists are safe without extra work.
6. **Fail closed, always, in v1.** The config knob exists only so org policy can make exceptions explicitly.
7. **LLM detector is additive-only and untrusted.** It cannot suppress findings from deterministic layers; injection in logs cannot lower the floor.
8. **Block before redact.** Deny-listed paths never enter context at all.

---

## 6. Phases & acceptance criteria

### Phase 1 — MVP (personal, deterministic only)
- `sanitize` with layers 1, 2, 3, 5. `/v1/detect`, `/v1/health`.
- Extension with `input`, `tool_call` (deny-list + rehydrate), `tool_result`, `before_provider_request` egress verifier, in-memory vault, `/sanitize status|show|test`.
- Fail-closed behaviour on `sanitize` down/timeout.
- Eval corpus with ≥ 300 planted items across ≥ 25 categories; CI gate: **100 % recall on the secrets categories, ≥ 95 % recall on structured PII.** Precision reported, not gated.
- Docs: install, config, "what it does not protect against."

**Done when:** a session where the agent runs `cat config.yaml` containing a DB URL with password, an AWS key pair, and a private key results in a provider payload containing none of them (asserted by a test harness that captures `before_provider_request`), and the agent can still successfully run `psql` against the DB via rehydrated `tool_call` args.

### Phase 2 — Quality
- GLiNER recognizer (layer 4). Format-preserving placeholders. `context` re-scan with "this should never fire" telemetry. Encrypted vault persistence for `/resume`. `/scrub reveal` with confirmation. Chunking + hash cache for large tool outputs. Latency budget: p95 < 300 ms for a 50 KB tool result on CPU.

### Phase 3 — Local LLM recognizer
- Ollama/llama.cpp integration with constrained JSON output, additive-only merge, injection test cases in evals (logs that try to talk the detector out of flagging).

### Phase 4 — Org edition
- `sanitize` deployed as a shared service (container, mTLS or SSO in front, stateless, no content logging, metrics = counts by category + policy version only).
- Central `sanitize.yaml` policy served from `/v1/policy`, local configs can only tighten.
- Extension gains `policy_url`, signed policy verification, and an "audit event" emitter (category counts, never values).
- Optional: OpenAI-/Anthropic-compatible gateway mode so non-pi clients get the same protection (vault then must round-trip via response headers or stay client-side via an SDK shim — decide then).

---

## 7. Open questions for the implementer

1. Does pi's compaction summarization request pass through the `context` and `before_provider_request` hooks? If not, hook `session_before_compact` and scrub `preparation` content explicitly.
2. Exact abort semantics inside `before_provider_request` (throw vs. `ctx.abort()`).
3. Which current small local model to recommend as the Phase 3 default (evaluate 2–3 on the eval corpus; prefer one with grammar-constrained output support in the chosen runtime).
4. GLiNER model variant and CPU latency on a typical laptop; whether to run it as a lazy-loaded recognizer only for `tool_result` sources above N bytes.
5. Whether pi's built-in `read` tool can be overridden instead of intercepted, to enforce the deny-list at the tool level as well as in `tool_call`.

---

## 8. What this does not do (say it in the README)

- Does not protect against a compromised local machine or a malicious pi extension (extensions run with full permissions).
- Does not scrub images or binary attachments.
- Does not make anything "anonymous" in the GDPR sense — placeholders are pseudonymization and are reversible by the local vault.
- Cannot guarantee zero misses on free-text secrets with no structure; that is exactly why layers 4 and 6 exist and why recall evals are a CI gate rather than a one-off.
