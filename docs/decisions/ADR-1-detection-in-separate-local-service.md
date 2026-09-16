# ADR-1: Detection in a separate local service, not in the extension

**Status:** Accepted
**Date:** 2026-09-15

## Context

pi-scrub has two natural homes for detection logic: inside the pi extension (TypeScript, in the
agent's process) or in a separate local process the extension calls over HTTP.

The detectors we want to run are overwhelmingly Python: Presidio (the span engine and
structured-PII recognizers), GLiNER (contextual NER for names, addresses, hostnames), the
gitleaks rule set loaded as Presidio pattern recognizers, Yelp `detect-secrets` plugins, and
an optional local LLM recognizer via Ollama or llama.cpp. Porting these to TypeScript would mean
reimplementing and then maintaining a fork of each; the model-based ones cannot be ported at all
without a Node inference runtime.

Beyond the library question, Phase 4 calls for the same detection logic to run as a shared,
stateless org service with a central policy. Detection that lives inside the extension cannot
be redeployed that way without a rewrite.

## Decision

Detection runs in `sanitize`, a standalone Python (FastAPI) service listening on
`127.0.0.1:7411`. The extension is a thin client: it POSTs text plus context hints to
`/v1/detect` and receives spans. The service is language-neutral (any client that can speak
HTTP gets the same detection), testable in isolation with its own test suite and eval corpus,
and is literally the binary that becomes the org server in Phase 4 — only the deployment and
policy change.

The extension's `session_start` hook verifies the service is reachable and auto-starts it if
it is not, so the extra process is not something the user manages by hand.

## Consequences

**Easier:**

- Best-in-class detectors are available immediately, and upgrading them is a `pip` bump.
- The service has a single, mockable contract (`/v1/detect`), so extension tests run against a
  fake API with no Python dependency, and service tests run against a corpus with no pi
  dependency.
- Org mode is a deployment change, not a code change. The gateway mode (`sanitize.gateway`)
  for non-pi clients also falls out of this for free.
- Detection latency and memory (GLiNER, LLM) are isolated from the agent's process.

**Harder:**

- One more process to run. Mitigated by auto-start in `session_start` and `scripts/dev.sh`.
- A network hop on every ingress hook, which is why the client has a hard timeout (4 s default)
  and why the fail-closed rule (ADR-6) exists: an unreachable service must never degrade to
  pass-through.
- The egress verifier cannot depend on the service (if the service is what failed, the last
  line of defense must still work), so a small regex-only subset of detection is duplicated
  in-process in `extension/src/egress.ts`. That duplication is deliberate.
