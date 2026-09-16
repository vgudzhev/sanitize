# ADR-2: Stateless service, client-side vault

**Status:** Accepted
**Date:** 2026-09-15

## Context

Pseudonymization needs a mapping from placeholder to real value (the vault) so that tool calls
can be rehydrated and the user can read real values. Something has to own that mapping. The
obvious options are the detection service (which already sees the text and could hand back
rewritten text plus a mapping) or the client extension.

Whoever holds the vault holds the ability to reverse every scrubbed session. In Phase 4 the
detection service becomes a shared, network-reachable component serving a whole team. If it
also held vaults, it would be the single most valuable target in the organization: a breach
would expose every secret every developer had ever scrubbed. It would also need per-user
storage, session affinity, and a retention policy, none of which a detector should have.

## Decision

`sanitize` is stateless. It receives text, returns spans, and retains nothing: no content
logging, no request storage, no knowledge of placeholders. It never sees the vault and never
learns what a placeholder maps to.

The vault lives in the client. In the pi extension it is an in-memory
`Map<placeholder, value>` (plus the reverse map) keyed per session, wiped on
`session_shutdown`. Optional persistence for `/resume` is encrypted (AES-256-GCM, key derived
from a passphrase via PBKDF2) and stored via `pi.appendEntry("scrub-vault", …)`, which pi
excludes from LLM context.

Gateway mode is the one documented exception: the local gateway sidecar holds the vault
in-process so that non-pi SDK clients need no changes. It binds loopback only and must never
be deployed as a shared service.

## Consequences

**Easier:**

- The shared org service is not a high-value target. A breach of it exposes at most in-flight
  text, never mappings, and it has nothing to retain.
- The service scales horizontally with no session affinity, no storage, and no per-user
  state. Metrics are category counts and policy version only.
- Sessions, exports, and `/share` output are safe without any coordination with the service
  (see ADR-5).
- Trust boundary is simple to state: real values and the vault never leave the machine.

**Harder:**

- Substitution and rehydration logic lives in the client, so it is implemented in TypeScript
  (`vault.ts`, `substitute.ts`) rather than reusing Presidio's anonymizer/deanonymizer. This is
  small: right-to-left span replacement and two map lookups.
- Every client (pi extension, gateway, any future SDK shim) reimplements the vault. The
  contract is simple enough that this is acceptable.
- `/resume` requires vault persistence, which requires a key. Without `SANITIZE_VAULT_KEY`
  set, resumed sessions show placeholders that cannot be rehydrated. This is the correct
  failure mode.
- Gateway mode carries plaintext in a long-lived process and inherits the loopback-only
  constraint permanently.
