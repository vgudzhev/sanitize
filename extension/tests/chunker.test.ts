import { describe, it, expect, vi } from "vitest";
import {
  chunkText,
  mergeSpans,
  detectChunked,
  CHUNK_SIZE,
  OVERLAP,
} from "../src/chunker.js";
import { ChunkCache } from "../src/chunk-cache.js";
import type { Span } from "../src/types.js";

const span = (start: number, end: number, score = 0.9, type = "T"): Span => ({
  start,
  end,
  type,
  score,
  detector: "test",
});

describe("chunkText", () => {
  it("returns a single chunk for short text", () => {
    expect(chunkText("hello")).toEqual(["hello"]);
    expect(chunkText("")).toEqual([""]);
  });

  it("splits long text with the requested overlap", () => {
    const text = "abcdefghijklmnopqrstuvwxyz"; // 26 chars
    const chunks = chunkText(text, 10, 3);
    expect(chunks).toEqual(["abcdefghij", "hijklmnopq", "opqrstuvwx", "vwxyz"]);
    for (let i = 1; i < chunks.length; i++) {
      expect(chunks[i].slice(0, 3)).toBe(chunks[i - 1].slice(-3));
    }
  });

  it("covers the full text with no gaps", () => {
    const text = "x".repeat(CHUNK_SIZE * 3 + 17);
    const chunks = chunkText(text);
    const stride = CHUNK_SIZE - OVERLAP;
    let covered = 0;
    chunks.forEach((chunk, i) => {
      const start = i * stride;
      expect(start).toBeLessThanOrEqual(covered);
      expect(text.slice(start, start + chunk.length)).toBe(chunk);
      covered = start + chunk.length;
    });
    expect(covered).toBe(text.length);
  });

  it("returns one chunk when text is exactly chunkSize", () => {
    const text = "y".repeat(CHUNK_SIZE);
    expect(chunkText(text)).toEqual([text]);
  });

  it("splits when text is one char over chunkSize", () => {
    const text = "y".repeat(CHUNK_SIZE + 1);
    const chunks = chunkText(text);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]).toHaveLength(CHUNK_SIZE);
    expect(chunks[1]).toHaveLength(OVERLAP + 1);
  });

  it("rejects overlap >= chunkSize", () => {
    expect(() => chunkText("a".repeat(20), 5, 5)).toThrow(RangeError);
  });
});

describe("mergeSpans", () => {
  it("passes through non-overlapping spans sorted", () => {
    const merged = mergeSpans([span(10, 20), span(0, 5)]);
    expect(merged).toEqual([span(0, 5), span(10, 20)]);
  });

  it("dedupes identical spans from overlapping chunks", () => {
    const merged = mergeSpans([span(100, 120), span(100, 120)]);
    expect(merged).toHaveLength(1);
  });

  it("keeps the highest score on overlap", () => {
    const merged = mergeSpans([span(0, 10, 0.5, "LOW"), span(5, 15, 0.9, "HIGH")]);
    expect(merged).toEqual([span(5, 15, 0.9, "HIGH")]);
  });

  it("prefers the longer span on a score tie", () => {
    const merged = mergeSpans([span(0, 10, 0.9, "SHORT"), span(0, 20, 0.9, "LONG")]);
    expect(merged).toEqual([span(0, 20, 0.9, "LONG")]);
  });

  it("allows adjacent spans", () => {
    const merged = mergeSpans([span(0, 5), span(5, 10)]);
    expect(merged).toHaveLength(2);
  });
});

describe("detectChunked", () => {
  const SECRET = "AKIAIOSFODNN7EXAMPLE";
  // Regex-style detector: finds every occurrence of SECRET in the chunk.
  const detect = vi.fn(async (text: string): Promise<Span[]> => {
    const spans: Span[] = [];
    let idx = text.indexOf(SECRET);
    while (idx !== -1) {
      spans.push(span(idx, idx + SECRET.length, 0.99, "AWS_ACCESS_KEY"));
      idx = text.indexOf(SECRET, idx + 1);
    }
    return spans;
  });

  it("scans small text whole without touching the cache", async () => {
    detect.mockClear();
    const cache = new ChunkCache();
    const text = `key=${SECRET}`;
    const spans = await detectChunked(text, detect, cache, 100, 10);
    expect(spans).toEqual([span(4, 4 + SECRET.length, 0.99, "AWS_ACCESS_KEY")]);
    expect(detect).toHaveBeenCalledTimes(1);
    expect(cache.size).toBe(0);
  });

  it("maps chunk-local spans back to original coordinates", async () => {
    detect.mockClear();
    const cache = new ChunkCache();
    const chunkSize = 100;
    const overlap = 10;
    const prefix = "-".repeat(250);
    const text = prefix + SECRET + "-".repeat(50);
    const spans = await detectChunked(text, detect, cache, chunkSize, overlap);
    expect(spans).toHaveLength(1);
    expect(spans[0].start).toBe(250);
    expect(spans[0].end).toBe(250 + SECRET.length);
    expect(text.slice(spans[0].start, spans[0].end)).toBe(SECRET);
  });

  it("finds a secret straddling a chunk boundary and dedupes it", async () => {
    detect.mockClear();
    const cache = new ChunkCache();
    const chunkSize = 100;
    const overlap = 30; // > SECRET.length so one chunk contains it fully
    // Place SECRET so it starts 5 chars before the first boundary (100).
    const start = chunkSize - 5;
    const text =
      "-".repeat(start) + SECRET + "-".repeat(300 - start - SECRET.length);
    const spans = await detectChunked(text, detect, cache, chunkSize, overlap);
    expect(spans).toHaveLength(1);
    expect(text.slice(spans[0].start, spans[0].end)).toBe(SECRET);
  });

  it("skips chunks previously found clean", async () => {
    detect.mockClear();
    const cache = new ChunkCache();
    const text = "clean ".repeat(100); // 600 chars
    const chunkSize = 100;
    const overlap = 10;
    const first = await detectChunked(text, detect, cache, chunkSize, overlap);
    expect(first).toEqual([]);
    const calls = detect.mock.calls.length;
    expect(calls).toBe(chunkText(text, chunkSize, overlap).length);

    const second = await detectChunked(text, detect, cache, chunkSize, overlap);
    expect(second).toEqual([]);
    expect(detect.mock.calls.length).toBe(calls); // no new network calls
  });

  it("never caches chunks that had findings", async () => {
    detect.mockClear();
    const cache = new ChunkCache();
    const text = "-".repeat(150) + SECRET + "-".repeat(150);
    await detectChunked(text, detect, cache, 100, 10);
    const chunks = chunkText(text, 100, 10);
    const dirty = chunks.filter((c) => c.includes(SECRET));
    const clean = chunks.filter((c) => !c.includes(SECRET));
    expect(dirty.length).toBeGreaterThan(0);
    for (const c of dirty) expect(cache.has(c)).toBe(false);
    for (const c of clean) expect(cache.has(c)).toBe(true);
  });
});
