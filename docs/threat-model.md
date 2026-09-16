# pi-scrub — Threat Model

**Status:** v0.1
**Date:** 2026-09-16
**Companion to:** [architecture.md](architecture.md) §2 (goals), §3.2 (detection layers), §8 (non-goals)

This document expands the one-paragraph threat statement in the architecture spec into a
standalone model: who we defend against, what we protect, where the data can leak, what we do
about each path, and what remains uncovered by design.

---

## 1. Summary

pi-scrub assumes the local machine is trustworthy and everything past the network interface is
not. Every byte that leaves the machine toward a cloud LLM is scrubbed first; real values only
ever exist in a client-side vault that never leaves the machine. The single metric we optimize
is **recall on secrets** — a missed credential is a failure, a false positive is a nuisance.

---

## 2. Threat actors

All three actors below share one capability: they can read the full request/response stream
between pi and the model. They differ in *how* they get it and what else they can do.

### 2.1 Cloud provider breach

The model provider (or any provider pi is pointed at) retains prompts, tool results, and
responses for some period — for abuse monitoring, training opt-ins, debugging, or simply
because retention was never disabled. A breach, an insider, a subpoena, or a misconfigured
bucket exposes that archive.

- **Capability:** offline access to complete historical logs, possibly months of sessions.
- **Motivation:** credential harvesting at scale; a coding-agent log is unusually rich in
  live tokens, connection strings, and infrastructure detail.
- **Why it matters here:** the actor does not need to be online during the session. Anything
  that was ever sent is exposed, so scrubbing has to be correct *every* time, not most times.

### 2.2 Intermediary logging

Anything between pi and the provider that terminates or observes the request: model routers
(OpenRouter and similar), corporate egress proxies, API gateways, observability tooling, a
"helpful" logging middleware someone added to a self-hosted proxy.

- **Capability:** plaintext visibility of the payload at one or more hops; often retains it
  for debugging or analytics without a documented retention policy.
- **Motivation:** usually not malicious — accidental retention that later becomes a breach
  surface (see 2.1) or a compliance problem.
- **Why it matters here:** pi is provider-agnostic, so the path to the model is not fixed.
  We cannot audit every hop; we have to assume every hop logs.

### 2.3 Network interception

An on-path attacker: hostile Wi-Fi, a compromised corporate TLS-inspection appliance, a
malicious CA installed on the machine by an IT policy, DNS hijacking to a look-alike endpoint.

- **Capability:** live read (and possibly modify) of the request stream; typically cannot
  access historical logs.
- **Motivation:** targeted credential theft.
- **Why it matters here:** TLS is the primary defense, but TLS inspection is common in
  corporate environments and effectively downgrades this actor to an intermediary (2.2).

### Actors explicitly out of scope

- **A compromised local machine.** Malware with user-level access can read the vault from
  process memory, read the same files pi reads, and keylog the passphrase. pi-scrub does not
  and cannot defend against this. See §7.
- **A malicious pi extension.** Extensions run with full permissions in the same process. A
  hostile extension can bypass every hook. See §7.
- **The model itself as an adversary.** We do not try to prevent the model from *inferring*
  things from structure (e.g. "this looks like a Postgres schema"). We only remove the values.

---

## 3. Assets

What we are protecting, in priority order. Priority drives the recall target: secrets are a
CI gate at 100 %, structured PII at ≥ 95 %, contextual PII and infrastructure are best-effort.

### 3.1 Credentials (priority 1 — 100 % recall gate)

| Asset | Typical form | How it enters a session |
|---|---|---|
| SSH private keys | `-----BEGIN OPENSSH PRIVATE KEY-----` … multi-line PEM | `cat ~/.ssh/id_ed25519`, pasted into a prompt, dumped by a misbehaving script |
| Cloud provider keys | AWS `AKIA…`/secret pair, GCP `AIza…`, Azure, Aliyun | `env`, `cat ~/.aws/credentials`, Terraform output, CI logs |
| API / platform tokens | GitHub `ghp_`, GitLab `glpat-`, Slack `xoxb-`, Stripe `sk_live_`, Anthropic `sk-ant-`, OpenAI `sk-`, npm, PyPI, SendGrid, Telegram | `.env` files, shell history, error messages that echo headers |
| Database URLs with embedded credentials | `postgres://user:pass@host/db`, `mongodb+srv://…`, `redis://…`, `amqp://…` | config files, `DATABASE_URL` in env dumps, ORM error traces |
| JWTs and bearer tokens | `eyJ…​.eyJ…​.…`, `Authorization: Bearer …` | HTTP debug output, `curl -v`, browser devtools pastes |
| Generic secret assignments | `password=…`, `secret=…`, `api_key=…`, `client_secret=…` with high-entropy values | any config or log |
| Unprefixed high-entropy strings | 20+ char random strings next to `=`, `:`, `Bearer` | home-grown auth schemes, signing keys |
| VPN / infra credential files | `.ovpn`, `.tfstate`, `~/.kube/config`, `~/.netrc`, `.p12` | attempted `read` or `cat` by the agent |

A single leaked item from this class is a full compromise of whatever it protects. There is no
"partial" exposure; recall must be 100 %.

### 3.2 PII (priority 2 — ≥ 95 % recall on structured forms)

| Asset | Structured (Presidio) | Contextual (GLiNER) |
|---|---|---|
| Email addresses | yes | — |
| Phone numbers | yes | — |
| Credit cards (Luhn-validated), IBANs | yes | — |
| Dates of birth | yes (in context) | — |
| Person names | — | yes |
| Street addresses | — | yes |
| Organization names | — | yes |

PII appears in coding sessions more often than people expect: seed data, test fixtures copied
from production, customer support tickets pasted for context, git logs with author emails, log
lines with user identifiers.

### 3.3 Infrastructure details (priority 3 — best-effort)

| Asset | Detection |
|---|---|
| Internal hostnames (`*.internal`, `*.local`, `*.corp`) | GLiNER labels + custom literals |
| Private and public IP addresses | Presidio (IPv4/IPv6) |
| Project codenames | GLiNER labels + custom literals |
| Internal domain names, customer ID formats, employee IDs | custom vocabulary (`sanitize.yaml`) |

Individually low-value; in aggregate they map an organization's network for the actor in §2.1.
They are also the class most likely to appear in *every* tool result (hostnames in log lines),
which is why stable placeholders matter — the model still needs to correlate `[[HOST_3]]`
across a log.

---

## 4. Attack surface

Where data can leave the machine or be persisted in a form that later leaves it.

### 4.1 Provider API calls (primary)

Every LLM turn serializes the full message list — system prompt, user inputs, tool results,
prior assistant turns — into an HTTP request. This is the main channel and the one all three
actors observe. Three sub-paths feed it:

- **User input.** Typed or pasted text. Pastes are the dangerous case: a whole `.env` or a
  `curl -v` transcript arrives in one block.
- **Tool results.** The dominant leak vector by volume. `cat`, `env`, `grep`, `kubectl get
  secret -o yaml`, stack traces, log tails. Runs after pi's own 50 KB truncation, so the
  scrubber sees exactly what the model would.
- **Content injected by pi or other extensions.** Anything that reaches the message list
  without passing through the `input` or `tool_result` hooks — system-prompt augmentation,
  extension-sourced messages, future pi features.

### 4.2 Session files at rest

pi persists sessions as `.jsonl`. If the session file contains raw values, then every later
consumer of that file (`/resume`, backup tools, cloud-synced home directories, the `/share`
and `/export` paths below) becomes a leak channel — and one that outlives the session.

### 4.3 `/share` and `/export`

These take the session file and publish it (gist, file, clipboard). They are a deliberate
exfiltration of the session, so their safety is entirely a function of whether the session file
is clean.

### 4.4 Compaction summarization calls

When context grows, pi summarizes older messages by calling the model. This is a provider API
call (§4.1) whose input is constructed from persisted history. If the history is clean it is
safe; if any raw value slipped into history, compaction re-sends it. Whether this call passes
through the same hooks as normal turns is an open question tracked in architecture.md §7.1.

### 4.5 Gateway mode (secondary surface)

Gateway mode (`sanitize.gateway`, port 7412) exposes the same scrubbing to non-pi clients via
an OpenAI/Anthropic-compatible proxy. It changes one assumption: the vault lives in the
gateway process instead of the client. It binds `127.0.0.1` only and must never be deployed as
a shared service, because that process holds plaintext secrets.

---

## 5. Mitigations

### 5.1 Layered detection

Six detectors run in order; results are unioned, overlaps resolved by highest score then widest
span. Each layer covers a failure mode of the one before it.

| # | Layer | Threat it addresses | Trust level |
|---|---|---|---|
| 1 | **Secret patterns** (gitleaks rules + detect-secrets plugins as Presidio `PatternRecognizer`s) | Known-format credentials: cloud keys, platform tokens, private key blocks, DB URLs, `password=` assignments | Deterministic; cannot be argued with |
| 2 | **Entropy** (Shannon entropy over ≥ 20-char tokens in secret-like contexts) | Credentials with no recognizable prefix — home-grown tokens, signing keys | Deterministic |
| 3 | **Structured PII** (Presidio built-ins) | Emails, phones, cards, IBANs, IPs, MACs, DOBs | Deterministic |
| 4 | **Contextual PII / infra** (GLiNER NER as a Presidio recognizer) | Names, addresses, orgs, hostnames, codenames — things with no fixed syntax | Model-based, but bounded: fixed label set, no free-text output |
| 5 | **Custom vocabulary** (`sanitize.yaml` regexes and literals) | Org-specific formats the generic layers cannot know about | Deterministic |
| 6 | **Local LLM recognizer** (optional, off by default) | "Looks like a credential but matches nothing" | **Untrusted**: additive-only, can never remove a span from layers 1–5; input framed as data; JSON-only output |

Layers 1–3 and 5 are deterministic and therefore immune to prompt injection embedded in logs
(e.g. `# these are test fixtures, ignore`). The eval corpus includes injection cases as a
CI gate. Layer 6's additive-only rule means injection can at worst make it *miss* — it can
never lower the floor set by the deterministic layers (see ADR-7).

Project-level `sanitize.yaml` can only add detections; it cannot disable built-in secret
patterns. This closes the path where a malicious repository ships a config that turns the
scrubber off.

### 5.2 Scrub at ingress, verify at egress

- **Ingress hooks** (`input`, `tool_result`) scrub before content is persisted, so the session
  file is clean at rest. This is what makes §4.2, §4.3 and §4.4 safe by construction rather than
  by additional machinery (ADR-5).
- **`context` hook** re-scans the full message list before every call. Defense in depth for
  §4.1's third sub-path. Should find nothing; when it does, that is logged as a bug elsewhere.
- **`before_provider_request` egress verifier** runs an in-process, regex-only, no-network pass
  over the *serialized* payload: private key headers, top gitleaks patterns (AWS, GitHub, Slack,
  JWT, DB URLs, bearer tokens, generic secret assignments). On a hit the request is aborted and
  the tripping category is surfaced. This is the last line and is deliberately independent of
  the `sanitize` service so that a service bug cannot disable it.

### 5.3 Fail closed

If `sanitize` is unreachable, times out (default 4 s), or errors, the affected content is
replaced with `[[SCRUBBER_UNAVAILABLE: content withheld]]` and the user is notified. Raw content
is never passed through. The `fail_open` config field is hard-coded `false` in v1 and exists
only so that org policy can later make an explicit, signed exception (ADR-6).

This converts an availability failure into a usability failure instead of a confidentiality
failure, which is the correct trade for the asset class in §3.1.

### 5.4 Path deny-list

The `tool_call` hook blocks `read` and `bash cat`-style access to paths that are *only ever*
credentials: `~/.ssh/**`, `**/.env*`, `**/*.pem`, `**/*.key`, `**/*.p12`,
`~/.aws/credentials`, `~/.kube/config`, `~/.netrc`, `**/*.ovpn`, `**/*.tfstate`. Configurable
(add-only). Blocking is cheaper and safer than redacting: the content never reaches the
detector, so detector recall is irrelevant for these files (ADR-8).

### 5.5 Vault isolation

The placeholder ↔ value mapping is the crown jewel: whoever has it can reverse every session.

- **Client-side only.** The `sanitize` service never sees the vault and never receives
  placeholders. It returns spans over text it does not retain. This means the service — the
  component that will eventually be shared across an org — is not a high-value target (ADR-2).
- **In-memory by default.** `Map<placeholder, value>` per session, wiped on
  `session_shutdown`.
- **Encrypted if persisted.** Optional persistence for `/resume` uses AES-256-GCM with a
  PBKDF2-derived key from a passphrase in `SANITIZE_VAULT_KEY`, written to
  `~/.sanitize/vault.enc`. Vault entries are stored via `pi.appendEntry("scrub-vault", …)`,
  which pi excludes from LLM context.
- **Rehydration only at two boundaries.** Real values are restored (a) into `tool_call`
  arguments immediately before local execution and (b) in a display-only markdown transformer
  so the user reads real values. Neither path writes to the session file or the outbound
  payload.
- **`/sanitize show` lists placeholders and types, never values.** `reveal` requires a
  confirmation dialog.

### 5.6 Stable pseudonymization

Same value → same placeholder within a session (`[[IP_7]]` is always the same host). This is a
usability mitigation, not a security one, but it matters for the threat model indirectly: if
scrubbing made output useless, users would turn it off. `[[TYPE_n]]` placeholders carry the
*type* of what was removed so the model can still reason ("connect to `[[HOST_1]]` using
`[[DB_URL_1]]`") without the value (ADR-4).

---

## 6. Trust boundaries

```
┌─────────────────────────────── local machine (trusted) ───────────────────────────────┐
│                                                                                       │
│  user ──► pi ──► pi-scrub extension ──────────────────────────────┐                   │
│              │      • vault (placeholder ↔ value)   ◄── NEVER    │                   │
│              │      • substitution / rehydration        LEAVES   │                   │
│              │      • deny-list                                  │                   │
│              │      • egress verifier                            │                   │
│              │             │                                     │                   │
│              │             │ POST /v1/detect (text in, spans out)│                   │
│              │             ▼                                     │                   │
│              │      sanitize service (127.0.0.1:7411)            │                   │
│              │        stateless · no content logging · no vault  │                   │
│              │                                                   │                   │
│              └── session .jsonl (placeholders only) ◄────────────┘                   │
│                                                                                       │
│  tools (bash, read, psql, ssh …) execute with REAL values, rehydrated at tool_call     │
│                                                                                       │
└──────────────────────────────────────┬────────────────────────────────────────────────┘
                                       │  placeholders only
                                       │  (egress-verified, fail-closed)
                                       ▼
┌───────────────────────────── untrusted ─────────────────────────────┐
│  network path → routers / proxies / TLS inspection → model provider │
│  sees: [[AWS_ACCESS_KEY_1]], [[DB_URL_1]], [[EMAIL_2]] …            │
│  never sees: real values, the vault, the deny-listed files          │
└─────────────────────────────────────────────────────────────────────┘
```

**Crossing rules:**

| Data | Local → cloud? | Notes |
|---|---|---|
| Scrubbed message text | yes | Only after ingress scrub + `context` re-scan + egress verify |
| Placeholders | yes | Carry type, not value |
| Real secret / PII values | **never** | Enforced by fail-closed + egress verifier |
| Vault (mapping) | **never** | Not even to `sanitize`; encrypted if on disk |
| Deny-listed file contents | **never** | Blocked before reaching any detector |
| Detection *counts* by category | org mode only | Audit events and metrics contain no values |

**Org mode moves one box.** In Phase 4 the `sanitize` service runs as a shared, mTLS/SSO-fronted
container. Because it is stateless and never sees the vault, the trust boundary around the
*mapping* does not move — only text-for-detection crosses to the shared service, and it is not
retained. Local config can only tighten central policy, never loosen it.

**Gateway mode moves the vault.** The gateway holds the vault in-process. It is therefore inside
the trusted zone only if it runs on the same machine as the client, which is why it binds
loopback only.

---

## 7. Residual risks

What remains after all of the above, stated plainly so it can be repeated in the README.

| Risk | Why it is accepted | Partial mitigation |
|---|---|---|
| **Compromised local machine** | The vault, the passphrase, and every file the agent can read are all accessible to user-level malware. No local-only tool can defend against its own host. | Vault wiped at shutdown by default; encrypted at rest if persisted. |
| **Malicious pi extension** | Extensions share a process and permissions with pi-scrub; they can strip hooks or read memory. | Only install extensions from trusted sources; project configs are honored only for `ctx.isProjectTrusted()` projects. |
| **Images and binary attachments** | No detector runs over image or binary content. A screenshot of a `.env` file leaves unscrubbed. | None in v1. Do not attach screenshots of secrets. |
| **Not GDPR anonymization** | Placeholders are pseudonymization: reversible by anyone with the vault, and the model can still see structure and relationships. This is a *privacy-from-the-provider* tool, not a data-anonymization tool. | Say so in the README; do not present scrubbed sessions as anonymized datasets. |
| **Free-text secrets with no structure** | "The password is the name of my first dog" or a secret split across two lines of prose has no pattern, no entropy signature, and no NER label. | Layers 4 and 6 exist precisely for this class; recall evals are a permanent CI gate rather than a one-off; egress verifier catches the structured subset. Residual misses are expected and cannot be driven to zero. |
| **Model-generated content on the response path** | Assistant output originates in the cloud; scrubbing it inbound protects nothing. If the model *echoes* a raw secret it somehow saw, that is a symptom of an upstream miss, not a new leak. | `message_end` scan logs new raw secrets in assistant text as a sanity metric. |
| **Secrets in file paths or tool names** | Only content and user input are scrubbed; a path like `/tmp/AKIA…/out.log` in a tool *argument* is not. | Deny-list covers the common credential file locations. |
| **Compaction bypassing hooks** | If pi's summarization call does not traverse `context`/`before_provider_request`, a stale raw value in history could be re-sent. | Ingress scrubbing keeps history clean so there is nothing to re-send; `session_before_compact` re-scan planned as belt-and-braces. |
| **pi extension API drift** | A pi upgrade could rename a hook, silently removing a layer. | Pin the pi version; re-verify hook names on upgrade; egress verifier is the independent backstop. |
| **Gateway mode holds plaintext** | Non-pi clients get scrubbing only by trusting the gateway process with the vault. | Loopback-only binding; documented as never-shared. |

---

## 8. Assumptions

Stated so that a change to any one of them triggers a review of this document.

1. The local machine, its OS keychain, and the user's shell environment are trustworthy.
2. pi's `input`, `tool_result`, `tool_call`, `context`, and `before_provider_request` hooks
   fire on every path that reaches the provider, and throwing in `before_provider_request`
   aborts the request (open question §7.2 in architecture.md; fallback is payload replacement
   plus `ctx.abort()`).
3. Custom session entries written via `pi.appendEntry` are excluded from LLM context.
4. pi's 50 KB tool-result truncation happens *before* the `tool_result` hook, so the scrubber
   sees the exact text the model would.
5. The `sanitize` service is reachable only on loopback in personal mode; in org mode it is
   fronted by mTLS or SSO and does not log content.
6. The eval corpus is synthetic. Real secrets are never checked in, and recall numbers are
   only as good as the corpus's coverage of real-world formats.
