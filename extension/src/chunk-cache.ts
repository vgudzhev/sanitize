import { createHash } from "node:crypto";

/**
 * Remembers SHA-256 hashes of text chunks that were recently scanned and
 * found clean, so repeated large tool outputs skip the network round-trip.
 *
 * Only clean chunks are cached: a chunk with findings must always be
 * re-scanned so the vault sees the raw value and can substitute it.
 */
export class ChunkCache {
  private clean = new Map<string, number>(); // hash → timestamp (ms)
  private maxAge: number;
  private maxEntries: number;

  constructor(maxAgeMs = 5 * 60 * 1000, maxEntries = 256) {
    this.maxAge = maxAgeMs;
    this.maxEntries = maxEntries;
  }

  /** True if `text` was scanned within `maxAge` and had no spans. */
  has(text: string): boolean {
    const key = hash(text);
    const stamp = this.clean.get(key);
    if (stamp === undefined) return false;
    if (Date.now() - stamp > this.maxAge) {
      this.clean.delete(key);
      return false;
    }
    return true;
  }

  /** Record that `text` was scanned and found clean. */
  markClean(text: string): void {
    const key = hash(text);
    // Re-insert so the Map's insertion order doubles as LRU order.
    this.clean.delete(key);
    this.clean.set(key, Date.now());
    this.evict();
  }

  /** Drop expired entries, then the oldest ones until under `maxEntries`. */
  private evict(): void {
    const now = Date.now();
    for (const [key, stamp] of this.clean) {
      if (now - stamp > this.maxAge) this.clean.delete(key);
    }
    while (this.clean.size > this.maxEntries) {
      const oldest = this.clean.keys().next().value;
      if (oldest === undefined) break;
      this.clean.delete(oldest);
    }
  }

  clear(): void {
    this.clean.clear();
  }

  get size(): number {
    return this.clean.size;
  }
}

function hash(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}
