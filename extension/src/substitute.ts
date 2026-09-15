import type { Span } from "./types.js";
import type { Vault } from "./vault.js";

export function substitute(text: string, spans: Span[], vault: Vault): string {
  if (spans.length === 0) return text;

  const sorted = [...spans].sort((a, b) => b.start - a.start);

  let result = text;
  for (const span of sorted) {
    const value = result.slice(span.start, span.end);
    if (!value) continue;

    const placeholder = vault.getPlaceholder(value, span.type);
    result = result.slice(0, span.start) + placeholder + result.slice(span.end);
  }

  return result;
}
