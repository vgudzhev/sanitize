# pi-scrub

Local sensitive-data scrubbing layer for the pi coding agent. Secrets and PII are replaced with stable, session-scoped placeholders (`[[AWS_ACCESS_KEY_1]]`, `[[EMAIL_2]]`) before leaving the machine. Real values are restored locally when tools execute and when text is displayed.

## Install

### scrubd (detection service)

```bash
cd scrubd
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
```

Start it:
```bash
uvicorn scrubd.app:app --port 7411
```

### Extension (pi integration)

```bash
cd extension
npm install
```

Link into pi (symlink into `~/.pi/agent/extensions/pi-scrub/` or configure in pi's extension settings).

## Configuration

Configuration is loaded from built-in defaults. Future versions will support `~/.pi/agent/scrub.yaml` and per-project `.pi/scrub.yaml`.

Key defaults:
- scrubd URL: `http://127.0.0.1:7411`
- Timeout: 4000ms
- Fail-closed: always (if scrubd is unreachable, content is withheld)

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

- `/scrub status` -- show scrubber health and redaction count
- `/scrub show` -- list all placeholders and their types (not values)
- `/scrub test <text>` -- test detection on arbitrary text

## Detection layers

| # | Layer | Catches |
|---|-------|---------|
| 1 | Secret patterns (gitleaks-derived) | AWS/GCP/Azure keys, GitHub/GitLab tokens, Slack, Stripe, JWTs, private key blocks, DB URLs with credentials, generic password assignments |
| 2 | Entropy | High-entropy strings in secret-like contexts (after `=`, `:`, `Bearer`, etc.) |
| 3 | Structured PII (Presidio) | Email, phone, IBAN, credit card, IP address, dates of birth |
| 5 | Custom vocabulary | User-defined patterns and literals (via config) |

## Running tests

```bash
# scrubd
cd scrubd && source .venv/bin/activate
pytest tests/ -v

# extension
cd extension && npm test

# evals (requires scrubd venv)
cd .. && source scrubd/.venv/bin/activate
python evals/generate_corpus.py
python evals/run_evals.py
```

## What this does NOT protect against

- A compromised local machine or a malicious pi extension (extensions run with full permissions)
- Image or binary attachment content
- GDPR-grade anonymization (placeholders are pseudonymization, reversible by the local vault)
- Free-text secrets with no structural pattern (layers 4 and 6, in later phases, target this)
- The model's own generated content on the response path (it originates in the cloud already)
- Secrets embedded in file paths or tool names (only file content and user input are scrubbed)
- False-positive tuning: layers 1 and 3 favor recall over precision, so benign strings may be redacted
