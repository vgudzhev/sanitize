# ADR-8: Block before redact (deny-listed paths never enter context)

**Status:** Accepted
**Date:** 2026-09-15

## Context

Some files exist only to hold credentials: `~/.ssh/*`, `.env*`, `*.pem`, `*.key`, `*.p12`,
`~/.aws/credentials`, `~/.kube/config`, `~/.netrc`, `*.ovpn`, `*.tfstate`. When the agent asks
to `read` one of these or run `cat` on it, there are two ways to protect the content: let the
tool run and rely on the detection layers to scrub the output, or refuse the tool call so the
content is never produced.

Relying on detection for these files is strictly weaker:

- Detector recall is high but not perfect, and these files are the highest-value targets in
  the threat model. A `.env` with an unusual variable name, a `kubeconfig` with a base64
  client certificate, or a `.tfstate` with a provider-specific token format are exactly the
  cases where a pattern might not exist yet.
- Scrubbing costs a round-trip, and a 2 MB `tfstate` costs a large one. Blocking costs
  nothing.
- Even a perfectly scrubbed `.env` gives the model nothing useful: a list of
  `KEY=[[SECRET_n]]` lines. There is no debugging value to preserve, so there is no
  usability trade-off in refusing.
- The refusal itself is informative. The model learns the file is off-limits and can ask the
  user, rather than silently receiving placeholders it might try to work around.

## Decision

The `tool_call` hook checks tool arguments against a path deny-list *before* rehydration and
before the tool executes. A match returns `{ block: true, reason }` and the tool never runs; the
file content never reaches any detector, the session, or the provider.

The built-in list covers the credential file locations above. Both global and project
`sanitize.yaml` can add patterns; neither can remove built-in ones (project config is honored
only for trusted projects). Patterns support `~` expansion and `*`/`**` globs; matching is
against the normalized absolute path.

Ordering within the pipeline: deny-list first, then rehydration, then execution, then
`tool_result` scrubbing of whatever the tool produced. "Block before redact" names the first
two steps.

## Consequences

**Easier:**

- For the highest-value files, the guarantee does not depend on detector recall at all. This
  is the one place in the system where the answer to "what if a pattern is missing?" is "it
  does not matter."
- Zero latency and zero service dependency for the common case of an agent poking at
  `~/.ssh` or `.env`.
- The deny-list is a plain function (`isDeniedPath`) with no state, trivially unit-tested with
  a fake home directory.

**Harder:**

- Coverage is only as good as the list, and the list is path-based. A secret in
  `config/settings.local.yaml` is not blocked and falls back to detection. The list is meant
  to be add-only and user-extended, not exhaustive.
- Path matching is a heuristic over tool arguments. `bash` in particular can reach a file
  through indirection (`cat $(echo ~/.ssh/id_rsa)`, `python -c "open(...)"`, a script that
  reads it). Those paths still go through `tool_result` scrubbing; the deny-list is a cheap
  first filter, not a sandbox. Whether pi's built-in `read` tool can be overridden to enforce
  this at the tool level as well is an open question (architecture.md §7.5).
- Legitimate workflows that need to read, for example, a `.env.example` will be blocked by the
  `**/.env*` glob and need an `allow` entry or a renamed file. False positives here are cheap
  to fix and accepted in line with the recall-first goal.
- Blocking is visible to the model. A model that repeatedly retries a blocked read wastes
  turns; the `reason` string should tell it to ask the user instead.
