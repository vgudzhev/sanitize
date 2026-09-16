import { describe, it, expect, afterEach, vi } from "vitest";
import { ChunkCache } from "../src/chunk-cache.js";

describe("ChunkCache", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("has() returns false for unknown text", () => {
    const cache = new ChunkCache();
    expect(cache.has("never seen")).toBe(false);
  });

  it("markClean() then has() returns true", () => {
    const cache = new ChunkCache();
    cache.markClean("clean output");
    expect(cache.has("clean output")).toBe(true);
    expect(cache.has("clean output ")).toBe(false);
  });

  it("expired entries return false", () => {
    vi.useFakeTimers();
    const cache = new ChunkCache(1000);
    cache.markClean("stale");
    vi.advanceTimersByTime(999);
    expect(cache.has("stale")).toBe(true);
    vi.advanceTimersByTime(2);
    expect(cache.has("stale")).toBe(false);
    expect(cache.size).toBe(0);
  });

  it("eviction respects maxEntries, dropping the oldest first", () => {
    const cache = new ChunkCache(60_000, 3);
    cache.markClean("a");
    cache.markClean("b");
    cache.markClean("c");
    expect(cache.size).toBe(3);
    cache.markClean("d");
    expect(cache.size).toBe(3);
    expect(cache.has("a")).toBe(false);
    expect(cache.has("b")).toBe(true);
    expect(cache.has("d")).toBe(true);
  });

  it("re-marking an entry refreshes its position", () => {
    const cache = new ChunkCache(60_000, 2);
    cache.markClean("a");
    cache.markClean("b");
    cache.markClean("a"); // "a" is now newest
    cache.markClean("c"); // should evict "b"
    expect(cache.has("a")).toBe(true);
    expect(cache.has("b")).toBe(false);
    expect(cache.has("c")).toBe(true);
  });

  it("clear() empties the cache", () => {
    const cache = new ChunkCache();
    cache.markClean("x");
    cache.markClean("y");
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.has("x")).toBe(false);
  });
});
