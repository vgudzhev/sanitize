# ADR-6: Fail closed, always, in v1

**Status:** Accepted
**Date:** 2026-09-15

## Context

The `sanitize` service is a separate process (ADR-1). It can be down, slow to start, out of
memory while loading GLiNER, mid-upgrade, or simply not installed. The extension has to decide
what to do with a tool result or user input when the detection call fails or exceeds its
timeout.

Two options:

- **Fail open:** pass the content through unscrubbed, perhaps with a warning. Preserves
  availability; the agent keeps working.
- **Fail closed:** withhold the content from the model. Preserves confidentiality; the agent
  is degraded until the service is back.

The threat model's first goal is recall on secrets, and the actors in threat-model.md §2 keep
logs indefinitely: a single unscrubbed `cat config.yaml` during a thirty-second service restart
is a permanent leak. Fail-open also creates an attack: anything that can crash or stall the
local service (a pathological input, resource exhaustion) becomes a way to disable scrubbing.
Whoever can make `sanitize` time out can exfiltrate.

The counter-argument is that fail-closed makes an availability problem into a workflow
problem, and users faced with a broken agent will disable the extension entirely. That risk is
real and is addressed by auto-start and clear notification rather than by weakening the rule.

## Decision

If the detection call errors, times out (`timeout_ms`, default 4000), or returns malformed
output, the affected content is replaced with `[[SCRUBBER_UNAVAILABLE: content withheld]]`
and the user is notified via `ctx.ui.notify(...)`. Raw content is never passed through.

The egress verifier in `before_provider_request` is likewise fail-closed: on any hit the
request is aborted and the tripping category is surfaced.

The `sanitize.fail_open` config field exists in `sanitize.yaml` but is hard-coded `false` in
v1 and ignored by the client. It is reserved so that, in Phase 4, an org policy can make an
explicit, signed exception for a specific deployment (for example, a fully local model where
scrubbing is optional overhead). Personal configs cannot enable it.

This is recorded as a project-wide convention in `CLAUDE.md`: if sanitize is unreachable,
block the request.

## Consequences

**Easier:**

- The confidentiality guarantee has no time-based holes. "Every byte that leaves the machine
  was scrubbed" is true even during outages.
- Denial-of-service against the scrubber does not become a bypass.
- The rule is simple to test: extension tests assert that a timed-out or erroring fake service
  yields the withheld marker and never the input.

**Harder:**

- A down service means a partially blind agent. Mitigations: `session_start` verifies
  reachability and auto-starts the service; the footer shows `sanitize: on/off`; the
  notification says exactly what happened.
- Latency budget matters more. A slow detector (GLiNER on CPU, LLM layer) that regularly
  exceeds 4 s produces withheld content rather than slow content, which is why Phase 2 sets a
  p95 < 300 ms target for 50 KB and why the LLM layer is off by default.
- `/sanitize off` exists for genuinely local-only sessions but requires confirmation, logs a
  warning, and re-enables on the next session. The escape hatch is deliberately
  inconvenient.
- The org-policy exception path must be signed and verified, or it becomes the bypass this
  ADR exists to prevent.
