# ADR-5: Session stays scrubbed at rest; rehydrate only at the tool boundary and display

**Status:** Accepted
**Date:** 2026-09-15

## Context

There are two places a scrubber can sit relative to the session store. It can scrub *on the way
out* — keep the session file with real values and clean the payload right before each provider
request — or it can scrub *on the way in*, so the persisted session never contains real values
and the outbound path needs no further work.

Scrubbing on the way out has one advantage (the session file is a faithful record) and several
serious problems:

- `/share`, `/export`, and `/resume` all read the session file. Each would need its own
  scrubbing pass, and any future pi feature that reads sessions would be a new leak channel.
- Compaction builds a summarization request from history. If history holds raw values, every
  compaction re-sends them, and it is an open question whether that request traverses the
  same hooks as a normal turn.
- The session file sits on disk, in backups, in cloud-synced home directories. A clean-at-rest
  file has nothing to leak from those.
- The set of hooks that must be perfect grows to include every path out, instead of the two
  paths in.

Choosing pi as the harness (architecture.md §1) was in part because pi lets an extension
transform `input` and `tool_result` *before* they are persisted, which makes the on-the-way-in
design possible.

## Decision

The session is scrubbed at ingress and stays scrubbed at rest. The `input` and `tool_result`
hooks substitute placeholders before pi persists the message, so `.jsonl` session files
contain placeholders only. `/share`, `/export`, `/resume`, and compaction are therefore safe by
construction.

Real values are restored in exactly two places, neither of which writes back to the session or
the outbound payload:

1. **Tool boundary.** The `tool_call` hook rehydrates `event.input` in place immediately
   before the tool executes, so `ssh [[HOST_1]]` runs against the real host and
   `psql [[DB_URL_1]]` connects. The tool's *output* then passes through `tool_result` and is
   scrubbed again before persistence.
2. **Display.** A `registerMarkdownTransformer` rehydrates text for rendering only, so the
   user reads real values in the terminal while the session file keeps placeholders.

The `context` and `before_provider_request` hooks remain as defense in depth for content that
reaches the message list by a path we did not hook. They should normally find nothing, and
when they do, that is logged as a bug in ingress scrubbing.

## Consequences

**Easier:**

- Every consumer of session files gets safety for free: sharing, exporting, resuming,
  compacting, backups, sync. No per-feature scrubbing passes.
- The set of hooks that must be correct for confidentiality is small and at the front:
  `input` and `tool_result`. Everything else is a backstop.
- The Phase 1 acceptance test is simple to state: capture `before_provider_request` and
  assert the payload contains none of the planted secrets, then assert `psql` still works via
  rehydrated args.

**Harder:**

- The session file is no longer a faithful record. A user reading the raw `.jsonl` sees
  placeholders, and a resumed session without the vault (no `SANITIZE_VAULT_KEY`) cannot be
  rehydrated. Vault persistence (ADR-2) exists to make `/resume` work.
- Rehydration in `tool_call` must be exhaustive across all argument shapes (nested objects,
  arrays, strings inside JSON strings), or a tool receives a placeholder and fails
  confusingly. Covered by extension tests.
- The display transformer must be display-only. If it ever fed back into the message list,
  it would reintroduce raw values. This invariant is worth a test.
- Content that is not text (images, binaries) does not pass through the substitution path and
  is not protected. Documented as a non-goal.
