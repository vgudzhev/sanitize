# Usage Guide

## Personal mode (single developer)

Personal mode is the default. Everything runs locally and nothing leaves your machine unscrubbed.

### 1. Start the detection service

```bash
cd sanitize
source .venv/bin/activate
uvicorn sanitize.app:app --port 7411
```

The service runs on `localhost:7411`. It is stateless — it receives text, returns spans, and never stores content.

### 2. Install the extension

```bash
cd extension
npm install
```

Link into pi:
```bash
mkdir -p ~/.pi/agent/extensions/pi-scrub
ln -s "$(pwd)/src/index.ts" ~/.pi/agent/extensions/pi-scrub/
```

Or add to pi's extension config.

### 3. Start using pi

Everything is automatic once the extension is loaded. The scrubbing pipeline:

1. **You type or paste** something → the extension sends it to sanitize → secrets and PII become placeholders like `[[AWS_ACCESS_KEY_1]]`
2. **A tool runs** (e.g., `cat config.yaml`) → tool output is scrubbed before the model sees it
3. **The model calls a tool** (e.g., `ssh [[HOST_1]]`) → placeholders are rehydrated to real values so the tool works
4. **The model responds** → placeholders in the response are rehydrated in your terminal so you see real values
5. **Before every API call** → an egress verifier scans the outgoing payload for raw secrets as a final safety net

The cloud model only ever sees placeholders. Your terminal shows real values.

### 4. Commands

| Command | What it does |
|---------|-------------|
| `/sanitize status` | Check if sanitize is reachable and see redaction count |
| `/sanitize show` | List all placeholders and their types (not values) |
| `/sanitize test <text>` | Test detection on arbitrary text |
| `/sanitize reveal` | Show real values behind placeholders (requires confirmation) |
| `/sanitize resume` | Restore vault from encrypted persistence after session restart |

### 5. Vault persistence

To preserve the vault across sessions (so `/resume` works), set:

```bash
export SANITIZE_VAULT_KEY="your-passphrase-here"
```

The vault is encrypted with AES-256-GCM and stored at `~/.sanitize/vault.enc`.

### 6. Configuration

Policy is loaded from built-in defaults, then merged with:
- `~/.pi/agent/sanitize.yaml` (global, user-level)
- `<project>/.pi/sanitize.yaml` (project-level, trusted projects only)

Example `sanitize.yaml`:
```yaml
detectors:
  gliner:
    labels:
      - person
      - address
      - organization
      - internal hostname
      - project codename
      - medical condition      # custom label
    threshold: 0.85
  llm:
    enabled: true
    model: llama3.2:3b

custom:
  patterns:
    - name: CUSTOMER_ID
      regex: "CUST-[0-9]{8}"
  literals:
    - "acme-internal.example"

allow:
  - "127.0.0.1"
  - "example.com"
```

### 7. Optional: Local LLM layer

For an extra detection layer that catches secrets no pattern matched:

```bash
# Install and start Ollama
ollama pull llama3.2:3b
```

Enable in config:
```yaml
detectors:
  llm:
    enabled: true
    model: llama3.2:3b
```

The LLM layer is additive-only — it can add detections but can never remove or override findings from the deterministic layers.

---

## Org mode (team deployment)

Org mode deploys sanitize as a shared service with a central policy that local configs can only tighten.

### Architecture

```
┌─────────────┐     HTTPS/mTLS      ┌──────────────────┐
│  developer   │ ──────────────────► │  reverse proxy    │
│  (pi + ext)  │ ◄────────────────── │  (nginx/caddy)    │
└─────────────┘                      │  terminates TLS   │
                                     │  validates OIDC   │
                                     └────────┬─────────┘
                                              │
                                     ┌────────▼─────────┐
                                     │  sanitize service │
                                     │  (container)      │
                                     │  bearer token auth│
                                     │  no content logs  │
                                     └──────────────────┘
```

### 1. Deploy the service

```bash
docker build -t sanitize .
docker run -d \
  -p 7411:7411 \
  -e SANITIZE_TOKEN=your-shared-secret \
  -e SANITIZE_POLICY_DIR=/policy \
  -v /path/to/signed-policy:/policy:ro \
  sanitize
```

Put a reverse proxy (nginx, Caddy, etc.) in front for mTLS or OIDC. The service itself does bearer token validation — the proxy handles certificate/identity.

### 2. Sign the central policy

```bash
# Generate key pair (once, keep private key secure)
python scripts/sign-policy.py keygen --out-dir keys/

# Sign your org policy
python scripts/sign-policy.py sign \
  --policy org-policy.yaml \
  --key keys/policy.key \
  --out-dir signed/

# Verify
python scripts/sign-policy.py verify \
  --policy-dir signed/ \
  --pubkey keys/policy.pub
```

Mount the `signed/` directory as `/policy` in the container.

### 3. Configure developer machines

Set environment variables:

```bash
export SANITIZE_URL="https://sanitize.corp.internal:7411"
export SANITIZE_TOKEN="your-shared-secret"
export SANITIZE_POLICY_URL="https://sanitize.corp.internal:7411"
export SANITIZE_PUBLIC_KEY="$(cat keys/policy.pub)"
```

Or in `~/.pi/agent/sanitize.yaml`:
```yaml
sanitize:
  url: https://sanitize.corp.internal:7411
```

### 4. Tightening-only local config

In org mode, local configs can only make the policy stricter:

| Can do | Cannot do |
|--------|-----------|
| Add deny paths | Remove deny paths |
| Add custom patterns/literals | Remove custom patterns |
| Add GLiNER labels | Remove GLiNER labels |
| Lower detection thresholds (more sensitive) | Raise thresholds (less sensitive) |
| Remove from allow list | Add to allow list |

`fail_open` is always `false` and cannot be overridden.

### 5. Audit events

Set up an audit endpoint to receive category counts (never content):

```bash
export SANITIZE_AUDIT_URL="https://audit.corp.internal/events"
```

Each scrub operation sends a fire-and-forget POST with:
```json
{
  "timestamp": "2026-09-16T12:00:00.000Z",
  "event": "scrub",
  "source": "tool_result",
  "categories": {"AWS_ACCESS_KEY": 1, "EMAIL_ADDRESS": 2},
  "total_spans": 3,
  "policy_version": "2026-09-16.abc123"
}
```

Audit is telemetry, not a security control — it never blocks the agent.

### 6. Metrics

The service exposes `/v1/metrics` with aggregate detection counts:

```bash
curl -H "Authorization: Bearer $SANITIZE_TOKEN" \
  https://sanitize.corp.internal:7411/v1/metrics
```

```json
{
  "requests": 1234,
  "categories": {
    "AWS_ACCESS_KEY": 15,
    "EMAIL_ADDRESS": 89,
    "PRIVATE_KEY": 3
  },
  "policy_version": "2026-09-16.abc123"
}
```

### Security guarantees

- **No content logging.** The service never logs request text. Metrics are category counts only.
- **Stateless.** No content is stored. The vault lives client-side, encrypted.
- **Fail closed.** If the service is unreachable, content is withheld with `[[SCRUBBER_UNAVAILABLE]]`.
- **Deterministic layers cannot be bypassed.** Prompt injection in logs has no effect on pattern-based detection.
- **LLM layer is untrusted.** It can only add detections, never suppress them.

### What this does NOT protect against

- A compromised local machine or a malicious extension
- Image or binary attachment content
- GDPR-grade anonymization (placeholders are reversible pseudonymization)
- The model's own generated content (it originates in the cloud)
- Secrets embedded in file paths or tool names (only content is scrubbed)
