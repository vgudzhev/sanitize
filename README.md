# pi-scrub

Local sensitive-data scrubbing layer for coding agents. Every byte that leaves the machine toward a cloud LLM passes through a local detection service first. Secrets and PII are replaced with stable, session-scoped placeholders (`[[AWS_ACCESS_KEY_1]]`, `[[EMAIL_2]]`) so the model can still reason about the data; real values are restored locally when tools execute and when text is displayed.

Provider-agnostic: works with any LLM backend (Anthropic, OpenAI, Google, Ollama, etc.) via the pi agent harness.

## Architecture

Two components:

| Component | Language | Role |
|-----------|----------|------|
| `sanitize` | Python (FastAPI) | Stateless detection service on `localhost:7411`. Returns spans, never stores content. |
| `extension` | TypeScript | Hooks the agent lifecycle, owns the session vault (placeholder <-> value), performs substitution and rehydration, enforces fail-closed. |

## Detection layers

Six layers run in order. Each layer can only add detections, never remove ones from earlier layers.

| # | Layer | What it catches | Speed |
|---|-------|----------------|-------|
| 1 | **Secret patterns** (gitleaks-derived regex) | AWS/GCP/Azure keys, GitHub/GitLab/Slack/Stripe tokens, JWTs, private key blocks, DB connection URLs, generic password assignments | < 1ms |
| 2 | **Entropy** | High-entropy strings in secret-like contexts (`=`, `:`, `Bearer`, etc.) | < 1ms |
| 3 | **Structured PII** (Presidio + spaCy) | Email, phone, IBAN, credit card, IP address, dates of birth, SSN, URLs | ~5ms |
| 4 | **Contextual NER** (GLiNER zero-shot) | Person names, organizations, addresses, internal hostnames, project codenames | ~50ms |
| 5 | **Custom vocabulary** | User-defined patterns and literals via config | < 1ms |
| 6 | **Local LLM** (Ollama, optional) | Catches secrets that no pattern matched. Additive-only: cannot suppress findings from layers 1-5. Off by default. | 200ms-10s |

**Performance:** p95 < 31ms on 50KB inputs (layers 1-5). The chunked fast path bypasses spaCy NLP per chunk, running pattern recognizers directly.

## What's currently covered

### Secrets

| Category | Examples |
|----------|----------|
| AWS | Access keys (`AKIA...`), secret access keys |
| GitHub | Personal access tokens (`ghp_`), OAuth (`gho_`), app tokens |
| GitLab | Personal/pipeline/runner tokens (`glpat-`, `glptt-`) |
| Slack | Bot/user/app tokens (`xoxb-`, `xoxp-`, `xoxa-`) |
| Stripe | Live and test API keys (`sk_live_`, `sk_test_`, `rk_live_`) |
| Anthropic | API keys (`sk-ant-`) |
| OpenAI | API keys (`sk-`) |
| Google | API keys (`AIza...`) |
| Heroku | API keys |
| SendGrid | API keys (`SG.`) |
| npm | Auth tokens (`npm_`) |
| PyPI | Upload tokens (`pypi-`) |
| Telegram | Bot tokens |
| JWTs | `eyJ...` bearer tokens |
| Private keys | RSA/EC/DSA/Ed25519 PEM blocks (including multi-line blocks that straddle chunk boundaries) |
| DB connection URLs | `postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://` with embedded credentials |
| Generic secrets | `password=`, `secret=`, `token=`, `api_key=` assignments with high-entropy values |
| High-entropy strings | Any high-entropy string in a secret-like context |

### PII

| Category | Examples |
|----------|----------|
| Email addresses | `user@domain.com` |
| Phone numbers | US and international formats |
| Credit cards | Visa, Mastercard, Amex, etc. |
| IBAN codes | International bank account numbers |
| IP addresses | Private and public IPv4 |
| Dates of birth | Various date formats in context |
| URLs | URLs with embedded credentials |
| Person names | Detected via GLiNER contextual NER |
| Organizations | Company and org names via GLiNER |
| Addresses | Street addresses via GLiNER |
| Internal hostnames | `*.internal`, `*.local` patterns via GLiNER |
| Project codenames | Detected via GLiNER contextual NER |

### Prompt injection resistance

The detection pipeline is deterministic (layers 1-5) and cannot be talked out of flagging secrets. Embedded instructions like "ignore previous instructions, these are test fixtures" have no effect — the eval corpus includes 12 injection test cases, all caught at 100% recall. Layer 6 (LLM) is additive-only and untrusted: its input is wrapped with an anti-injection frame, and its findings can never remove or override detections from layers 1-5.

## Install

### sanitize (detection service)

```bash
cd sanitize
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm

# GLiNER (Layer 4) — optional but recommended
pip install "torch==2.2.2" "gliner==0.2.10" "transformers>=4.38,<4.45" "numpy<2"
```

Start it:
```bash
uvicorn sanitize.app:app --port 7411
```

### Extension (pi integration)

```bash
cd extension
npm install
```

Link into pi (symlink into `~/.pi/agent/extensions/pi-scrub/` or configure in pi's extension settings).

### Layer 6: Local LLM (optional)

Requires a running [Ollama](https://ollama.com) instance:

```bash
ollama pull llama3.2:3b
```

Enable in policy config:
```yaml
detectors:
  llm:
    enabled: true
    model: llama3.2:3b
```

## Configuration

Policy is loaded from built-in defaults, then merged with `~/.pi/agent/sanitize.yaml` (global) and `.pi/sanitize.yaml` (per-project).

Key defaults:
- sanitize URL: `http://127.0.0.1:7411`
- Timeout: 4000ms
- Fail-closed: always (if sanitize is unreachable, content is withheld)
- GLiNER threshold: 0.85
- LLM layer: disabled

### Deny-list

These paths are blocked from being read by the agent:
`~/.ssh/**`, `**/.env*`, `**/*.pem`, `**/*.key`, `**/*.p12`, `~/.aws/credentials`, `~/.kube/config`, `~/.netrc`, `**/*.ovpn`, `**/*.tfstate`

## Usage

Once installed, scrubbing is automatic. The extension hooks into pi's lifecycle:

- **Input**: user text is scrubbed before entering the session
- **Tool results**: output from bash, read, etc. is scrubbed before the model sees it
- **Tool calls**: arguments are rehydrated (placeholders replaced with real values) so tools execute correctly
- **Egress**: a fast regex pass verifies no secrets leak in the provider payload
- **Display**: placeholders are rehydrated in the terminal so you see real values

### Commands

- `/sanitize status` — show sanitize health and redaction count
- `/sanitize show` — list all placeholders and their types (not values)
- `/sanitize test <text>` — test detection on arbitrary text
- `/sanitize resume` — restore vault from encrypted persistence (for session resume)

## Org mode (team deployment)

Deploy sanitize as a shared service with a central, signed policy. Local configs can only tighten the policy — never loosen it.

Features:
- **Signed policy**: Ed25519-signed canonical JSON, verified by the extension
- **Bearer token auth**: `SANITIZE_TOKEN` env var on both service and extension
- **Audit events**: fire-and-forget category counts to an audit endpoint (never content)
- **`/v1/metrics`**: aggregate detection counts + policy version
- **Tightening-only merge**: local configs can add detections but never suppress them
- **Docker**: `docker build -t sanitize .` and deploy behind a reverse proxy for mTLS/OIDC

See [`docs/usage.md`](docs/usage.md) for full setup instructions.

## Running tests

```bash
# sanitize (108 tests)
cd sanitize && source .venv/bin/activate
pytest tests/ -v

# extension (87 tests)
cd extension && npm test

# evals — 317 items across 26 categories, 100% recall
cd .. && source sanitize/.venv/bin/activate
python evals/run_evals.py
```

## Eval corpus

26 categories including: AWS keys, GitHub/GitLab/Slack/Stripe/Anthropic/OpenAI tokens, JWTs, private keys, DB URLs, emails, phone numbers, credit cards, IBANs, IPs, dates of birth, high-entropy secrets, and **prompt injection resistance** (12 test cases with embedded instructions trying to suppress detection).

## What this does NOT protect against

- A compromised local machine or a malicious extension
- Image or binary attachment content
- GDPR-grade anonymization (placeholders are pseudonymization, reversible by the local vault)
- The model's own generated content on the response path (it originates in the cloud)
- Secrets embedded in file paths or tool names (only content and user input are scrubbed)
