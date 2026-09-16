import type { Span } from "./types.js";
import type { ChunkCache } from "./chunk-cache.js";

export const CHUNK_SIZE = 4096; // characters
export const OVERLAP = 256; // overlap to catch secrets spanning chunk boundaries

/**
 * Split `text` into overlapping chunks. Text at or under `chunkSize` is
 * returned as a single chunk. Consecutive chunks share `overlap` characters
 * so a secret straddling a boundary is fully contained in at least one chunk.
 */
export function chunkText(
  text: string,
  chunkSize = CHUNK_SIZE,
  overlap = OVERLAP,
): string[] {
  if (text.length <= chunkSize) return [text];
  if (overlap >= chunkSize) {
    throw new RangeError("overlap must be smaller than chunkSize");
  }
  const chunks: string[] = [];
  let offset = 0;
  while (offset < text.length) {
    chunks.push(text.slice(offset, offset + chunkSize));
    offset += chunkSize - overlap;
  }
  return chunks;
}

/**
 * Merge spans from overlapping chunks. Spans are assumed to already be in
 * original-text coordinates. Overlapping spans collapse to one, keeping the
 * highest score (ties go to the longer span).
 */
export function mergeSpans(spans: Span[]): Span[] {
  if (spans.length <= 1) return spans;
  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: Span[] = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    const span = sorted[i];
    const last = merged[merged.length - 1];
    if (span.start >= last.end) {
      merged.push(span);
      continue;
    }
    const spanLen = span.end - span.start;
    const lastLen = last.end - last.start;
    if (
      span.score > last.score ||
      (span.score === last.score && spanLen > lastLen)
    ) {
      merged[merged.length - 1] = span;
    }
  }
  return merged;
}

export type DetectFn = (text: string) => Promise<Span[]>;

/**
 * Detect spans in `text`, chunking large inputs and skipping chunks the
 * cache has already seen clean. Returned spans are in original-text
 * coordinates. Small inputs (≤ chunkSize) are scanned whole, exactly as
 * before chunking existed.
 */
export async function detectChunked(
  text: string,
  detect: DetectFn,
  cache: ChunkCache,
  chunkSize = CHUNK_SIZE,
  overlap = OVERLAP,
): Promise<Span[]> {
  if (text.length <= chunkSize) return detect(text);

  const chunks = chunkText(text, chunkSize, overlap);
  const stride = chunkSize - overlap;
  const perChunk = await Promise.all(
    chunks.map(async (chunk, i): Promise<Span[]> => {
      if (cache.has(chunk)) return [];
      const spans = await detect(chunk);
      if (spans.length === 0) {
        cache.markClean(chunk);
        return [];
      }
      const base = i * stride;
      return spans.map((s) => ({ ...s, start: s.start + base, end: s.end + base }));
    }),
  );
  return mergeSpans(perChunk.flat());
}
