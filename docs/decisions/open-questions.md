# §7 Open Questions — Status

Tracking the open questions from architecture.md §7 with their resolution or current status.

## Q1: Compaction and hook coverage
**Status:** Mitigated

Whether pi's compaction summarization request traverses the `context` and
`before_provider_request` hooks has not been verified against pi. Rather than depend on the
answer, the extension hooks `session_before_compact` directly
(`extension/src/index.ts`, `api.on("session_before_compact", ...)`). It shares the
`rescanMessages` helper with the `context` hook: every text block in `event.messages` is sent
back to `/detect` with `hints.source = "session_before_compact"`, any hit is substituted from
the vault, and a `sanitize_compact_rescan_fired` session entry is appended so a hit is visible
as a bug report rather than silently absorbed. Fail-closed applies: if sanitize is unreachable
the messages are replaced with `[[SCRUBBER_UNAVAILABLE: content withheld]]`.

Note the event shape (`SessionBeforeCompactEvent` in `extension/src/types.ts`) exposes
`messages`, not a separate `preparation` field as §7.1 anticipated; the re-scan covers the
message list that feeds the summary.

Covered by `extension/tests/hooks.test.ts` (`describe("session_before_compact")`). See also
`docs/threat-model.md` §4.4 and the "Compaction bypassing hooks" row in its mitigation table.

## Q2: Abort semantics in before_provider_request
**Status:** Resolved

The extension uses `ctx.abort()` followed by `return`; it does not throw. `ExtensionContext`
declares `abort(): void` (`extension/src/types.ts`). In `extension/src/index.ts` the
`before_provider_request` handler:

1. Runs `verifyEgress` over the JSON-serialized payload. On a violation it notifies the user
   with the tripped categories, calls `ctx.abort()`, and returns.
2. Otherwise checks the payload for any raw vault value of 8+ characters. On a hit it appends
   `sanitize_context_rescan_fired`, notifies, and calls `ctx.abort()`.

The fallback in architecture.md §3 ("replace the payload with a minimal stub and abort") is not
implemented; abort alone is relied on. Whether throwing inside the hook also aborts the
provider call remains unverified and is deliberately not used.

Covered by `extension/tests/integration.test.ts`, which asserts `ctx.abort` is not called for
a scrubbed payload and is called for an unscrubbed one.

## Q3: Phase 3 default local model
**Status:** Resolved (default chosen; comparative eval not run)

`llama3.2:3b` via Ollama. `DEFAULT_MODEL = "llama3.2:3b"` in
`sanitize/sanitize/recognizers/llm.py`; the same fallback appears in
`_build_llm_recognizer` in `sanitize/sanitize/engine.py`, with the policy key
`detectors.llm.model` overriding it.

The §7.3 preference for grammar-constrained output is met: `LlmRecognizer._call_ollama` posts
to `/api/chat` with `format` set to a JSON schema (`_RESPONSE_SCHEMA`), `temperature: 0.0`,
`num_predict: 2048`, and a 10 s timeout. Output is validated (offsets in range, score >= 0.3)
and scores are capped at 0.79 so the layer can never outrank deterministic detectors. The
layer is off by default (`detectors.llm.enabled: false` in `sanitize/sanitize/policy.py`) and
is skipped for texts longer than `CHUNK_THRESHOLD` (4096 chars).

Not done: the "evaluate 2-3 models on the eval corpus" step. `evals/` has no LLM-layer
comparison; the choice reflects size, Ollama availability, and structured-output support
rather than measured recall. See ADR-7 for the untrusted/additive-only treatment.

## Q4: GLiNER variant, latency, and gating
**Status:** Partially resolved

**Variant.** `urchade/gliner_multi_pii-v1` (`DEFAULT_MODEL` in
`sanitize/sanitize/recognizers/gliner.py`), pinned in docs to `gliner==0.2.10` with
`torch==2.2.2`. Labels default to person, address, organization, internal hostname, project
codename; threshold 0.85 (`sanitize/sanitize/policy.py`). Note that
`sanitize/sanitize/engine.py` falls back to `0.5` if the policy omits the threshold key, which
differs from the recognizer's own 0.85 default; in practice the shipped policy always sets it.

**Lazy loading.** Implemented, but at the model level rather than the source level.
`GlinerRecognizer._ensure_model` loads the model on the first `analyze` call, not at service
startup, and caches an unavailable state if `gliner` is not installed or loading fails (the
layer then returns no results and logs once).

**Source/size gating.** Not implemented. The recognizer is added to the Presidio registry
unconditionally in `_build_analyzer` and runs on every source (`input`, `tool_result`,
`context`, `session_before_compact`); `hints.source` is not consulted. It is also included in
`_get_pattern_recognizers`, so for texts over `CHUNK_THRESHOLD` it runs per chunk on any chunk
that passes `_CHUNK_PREFILTER` and is not in the clean-chunk cache. There is no "only for
`tool_result` above N bytes" rule.

**Latency.** README cites ~50 ms for the layer; there is no laptop benchmark in the repo and
`evals/` does not measure per-layer timing. The `stats.ms` field on `/detect` responses is the
place to gather this.

## Q5: Overriding pi's built-in read tool
**Status:** Open (not investigated)

Whether pi allows replacing the built-in `read` tool has not been looked into. The deny-list
is enforced by interception only: the `tool_call` hook in `extension/src/index.ts` calls
`extractPathFromToolCall`, which reads `file_path` for `read`/`edit`/`write` and pulls the
first path argument of `cat`/`head`/`tail`/`less`/`more`/`bat` out of `bash` commands, then
checks it with `isDeniedPath` (`extension/src/denylist.ts`). A match returns
`{ block: true, reason }` before rehydration and before the tool runs.

Limits are as recorded in ADR-8: matching is a heuristic over tool arguments, and `bash` can
reach a file through indirection that the regex does not see. Those cases fall back to
`tool_result` scrubbing. A tool-level override would close that gap for `read` specifically
and remains the follow-up.
