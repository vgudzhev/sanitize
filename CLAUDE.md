# pi-scrub

Local sensitive-data scrubbing layer for coding agents.

## Architecture
Read docs/architecture.md first — it's the spec.

## Stack
- scrubd: Python 3.12+, FastAPI, Presidio, GLiNER, gitleaks rules
- extension: TypeScript, targets pi coding agent extension API
- evals: Python, synthetic corpus

## Conventions
- All detection returns spans (start, end, type, score), never rewritten text
- Service is stateless, vault is client-side only
- Fail closed: if scrubd is unreachable, block the request

## Commands
- cd scrubd && uvicorn scrubd.app:app --port 7411
- cd extension && npm test

## Phases
Implement Phase 1 (MVP) first. See §6 in architecture.md.
