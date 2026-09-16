# ADR-4: Pseudonymize with stable placeholders, not redact

**Status:** Accepted
**Date:** 2026-09-15

## Context

Once a span is detected, it can be redacted (replaced with a fixed marker such as
`[REDACTED]` or `***`) or pseudonymized (replaced with a placeholder that is unique to the value
and stable across the session, such as `[[IP_7]]`).

The second goal in the threat model is *useful output*: a scrubbed log must still be
debuggable by the model. Redaction destroys the information the model needs most. If three
hosts in a log all become `[REDACTED]`, the model cannot tell that the timeout on line 40 and
the retry on line 212 involve the same host. If a DB URL becomes `***`, the model cannot ask the
user to run `psql` against it, because nothing identifies which URL. A scrubber that makes the
agent useless will be turned off, and a scrubber that is turned off protects nothing.

Redaction is also irreversible, which rules out rehydrating tool arguments (ADR-5): the model
could never say `ssh [[HOST_1]]` and have it work.

## Decision

Detected values are replaced with typed, numbered placeholders of the form `[[TYPE_n]]`:
`[[EMAIL_2]]`, `[[AWS_ACCESS_KEY_1]]`, `[[IP_7]]`, `[[PRIVATE_KEY_1]]`.

- **Stable:** the same value always maps to the same placeholder within a session. The vault
  reverse map (`value → placeholder`) enforces this; a new placeholder is minted only when the
  value has not been seen.
- **Typed:** the placeholder carries what was removed, so the model can reason about it
  ("connect to `[[HOST_1]]` with `[[DB_URL_1]]`") without knowing the value.
- **Numbered per type, per session:** `[[IP_1]]`, `[[IP_2]]`, … Numbers are not global
  counters.
- **Delimiters `[[ ]]`:** rare in real logs and code, survive markdown rendering, tokenize
  cleanly. Configurable.
- **Multi-line secrets collapse to one line:** a private key block becomes a single
  `[[PRIVATE_KEY_1]]` line so structure around it is preserved without leaking its length.
- **Format-preserving mode (Phase 2):** for IPs, hostnames, UUIDs, and emails, optionally
  generate synthetic values of the same shape (`10.0.4.17` → `10.191.33.8`, consistently) so
  log parsers and the model's own pattern matching keep working. Synthetic values must never
  collide with real values in the same session, and the egress verifier must recognize them
  as fakes.

## Consequences

**Easier:**

- The model can correlate placeholders across a log, across turns, and across tool results,
  which is what makes agentic debugging work at all.
- Rehydration is possible (ADR-5): a placeholder in a tool call maps back to exactly one
  value.
- Users can inspect what was removed by category with `/sanitize show` without ever
  displaying a value.
- Redacted-count metrics (`sanitize: on · 14 redacted`) and org audit events are natural
  by-products of the vault.

**Harder:**

- This is pseudonymization, not anonymization. Anyone with the vault can reverse it, and the
  model still sees structure, cardinality, and relationships. It must never be described as
  GDPR-grade anonymization (threat-model.md §7).
- Placeholders leak *type* and *count*: a provider can tell that a session contained three AWS
  keys and one private key. This is accepted; the values are what matter.
- The vault becomes a stateful, security-critical component with its own persistence and
  encryption story (ADR-2).
- Format-preserving mode adds a collision-avoidance obligation and a second placeholder
  grammar that the egress verifier must understand. Gateway mode does not support it because
  streaming rehydration needs the bracketed form.
