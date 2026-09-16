# Quick Start

Get pi-scrub running in under 5 minutes. This guide covers personal mode (single developer, everything local). For team deployment, see [usage.md](usage.md).

## Prerequisites

- Python 3.12+
- Node.js 18+
- Claude Code or pi agent installed

## 1. Clone and install

```bash
git clone https://github.com/vgudzhev/sanitize.git
cd sanitize
```

### Detection service

```bash
cd sanitize
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m spacy download en_core_web_sm
```

For person/org/address detection (recommended):

```bash
pip install "torch==2.2.2" "gliner==0.2.10" "transformers>=4.38,<4.45" "numpy<2"
```

### Extension

```bash
cd ../extension
npm install
```

## 2. Start the service

```bash
cd ../sanitize
source .venv/bin/activate
uvicorn sanitize.app:app --port 7411
```

Verify it's running:

```bash
curl http://localhost:7411/v1/health
# {"status":"ok","version":"0.2.0","detectors":["secrets","entropy","presidio","gliner","custom"]}
```

## 3. Link the extension

**Claude Code:**
```bash
mkdir -p ~/.claude/extensions/pi-scrub
ln -s "$(pwd)/../extension/src/index.ts" ~/.claude/extensions/pi-scrub/
```

**pi:**
```bash
mkdir -p ~/.pi/agent/extensions/pi-scrub
ln -s "$(pwd)/../extension/src/index.ts" ~/.pi/agent/extensions/pi-scrub/
```

## 4. Try it

Start your agent (Claude Code or pi) as usual. Paste something with a secret:

```
My AWS key is AKIAIOSFODNN7EXAMPLE and password is hunter2
```

You'll see the model receive:

```
My AWS key is [[AWS_ACCESS_KEY_1]] and password is [[GENERIC_SECRET_1]]
```

Your terminal still shows the real values. The cloud model never sees them.

## 5. Test detection directly

```bash
curl -s -X POST http://localhost:7411/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "email me at alice@corp.com, key AKIAIOSFODNN7EXAMPLE"}' | python3 -m json.tool
```

Output shows each detected span with type, position, and score.

## Commands

Once running inside your agent:

| Command | What it does |
|---------|-------------|
| `/sanitize status` | Check service health and redaction count |
| `/sanitize show` | List all placeholders and their types |
| `/sanitize test <text>` | Test detection on any text |
| `/sanitize reveal` | Show real values (requires confirmation) |
| `/sanitize resume` | Restore vault after session restart |

## Configuration

Create `~/.claude/sanitize.yaml` (or `~/.pi/agent/sanitize.yaml` for pi) to customize:

```yaml
# Add custom patterns
custom:
  patterns:
    - name: EMPLOYEE_ID
      regex: "EMP-[0-9]{6}"
  literals:
    - "acme-internal.corp"

# Add GLiNER labels for domain-specific entities
detectors:
  gliner:
    labels:
      - person
      - address
      - organization
      - internal hostname
      - project codename
      - medical condition

# Allowlist values that aren't secrets
allow:
  - "127.0.0.1"
  - "example.com"
  - "test@example.com"
```

Project-level overrides go in `<project>/.claude/sanitize.yaml` (or `<project>/.pi/sanitize.yaml`).

## Vault persistence

To keep placeholders across sessions:

```bash
export SANITIZE_VAULT_KEY="your-passphrase"
```

Then use `/sanitize resume` after restarting your agent.

## Optional: Local LLM layer

For an extra detection layer that catches secrets no pattern matched:

```bash
ollama pull llama3.2:3b
```

Enable in config:

```yaml
detectors:
  llm:
    enabled: true
    model: llama3.2:3b
```

This layer is additive-only — it can never override or suppress detections from the deterministic layers.

## What's next

- [Usage guide](usage.md) — full reference for personal and org modes
- [Architecture](architecture.md) — how the detection pipeline works
