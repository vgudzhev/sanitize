# ADR-3: Spans, not rewritten text, as the service contract

**Status:** Accepted
**Date:** 2026-09-15

## Context

A detection service can return either the rewritten text (with sensitive values already
replaced) or a list of spans (`start`, `end`, `type`, `score`, `detector`) over the original
text, leaving replacement to the caller. Presidio's anonymizer supports the former; LLM Guard
returns rewritten text and is non-reversible.

Three properties of this project push against rewritten text:

1. Layer 6 is a local LLM. If a model-based detector returns rewritten text, it can corrupt
   content: drop lines, "fix" code, hallucinate a replacement, or be talked into rewriting by
   injected instructions in a log. A span-only contract means the worst it can do is emit a
   bad span, which the merge step can bound.
2. Six detectors run in parallel and their results have to be merged. Merging six rewritten
   copies of the same text is intractable; merging six lists of offsets over one immutable
   text is a sort and a sweep.
3. Placeholder policy belongs to the client (ADR-2). The service does not know the vault, so
   it cannot know whether a value already has a placeholder, what number to mint, or whether
   format-preserving mode is on.

## Decision

`POST /v1/detect` returns spans over the exact input text, never modified text:

```json
{ "spans": [ { "start": 120, "end": 168, "type": "AWS_ACCESS_KEY", "score": 0.99,
               "detector": "regex:gitleaks/aws" } ],
  "stats": { "ms": 42, "detectors_run": ["denylist","regex","presidio","gliner"] },
  "policy_version": "2026-09-15.1" }
```

The engine unions spans from all layers and resolves overlaps by highest score, then widest
span. The client applies replacements right-to-left so earlier offsets stay valid.

This is a project-wide convention (recorded in `CLAUDE.md`): all detection returns spans,
never rewritten text.

## Consequences

**Easier:**

- Adding a detector is adding a span source. No detector can damage text it did not flag.
- The untrusted LLM layer (ADR-7) is safe to include: its output is validated as offsets into
  known text, and the merge rule makes it additive-only by construction.
- The client owns placeholder minting, reuse, numbering, delimiters, and format-preserving
  mode, all of which need vault state the service must not have.
- Evals compare span sets against planted ground truth directly; recall per category is a set
  operation.
- The in-process egress verifier and the service share the same mental model even though they
  share no code.

**Harder:**

- Offsets must be exact. Chunking large tool outputs (Phase 2) means offset translation back
  to the original text, and multi-line spans (private key blocks) that straddle chunk
  boundaries need explicit handling.
- The client must handle overlapping and adjacent spans correctly; a bug there is a leak. This
  is covered by extension tests rather than trusting the service to have done it.
- Two round-trips of the full text (in, and then locally rewritten) instead of one. For 50 KB
  tool results this is negligible next to detector latency.
