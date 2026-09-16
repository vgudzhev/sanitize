# pi-scrub

Local sensitive-data scrubbing layer for coding agents.

## Architecture
Read docs/architecture.md first — it's the spec.

## Stack
- sanitize: Python 3.12+, FastAPI, Presidio, GLiNER, gitleaks rules
- extension: TypeScript, targets pi coding agent extension API
- evals: Python, synthetic corpus

## Conventions
- All detection returns spans (start, end, type, score), never rewritten text
- Detection service is stateless, vault is client-side only (except gateway mode: local sidecar with in-process vault)
- Fail closed: if sanitize is unreachable, block the request

## Commands
- cd sanitize && uvicorn sanitize.app:app --port 7411
- cd sanitize && uvicorn sanitize.gateway:gateway --host 127.0.0.1 --port 7412
- cd extension && npm test

## Phases
Implement Phase 1 (MVP) first. See §6 in architecture.md.
