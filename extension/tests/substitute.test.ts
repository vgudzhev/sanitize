import { describe, it, expect, beforeEach } from "vitest";
import { substitute } from "../src/substitute.js";
import { Vault } from "../src/vault.js";
import type { Span } from "../src/types.js";

describe("substitute", () => {
  let vault: Vault;

  beforeEach(() => {
    vault = new Vault();
  });

  it("returns original text when no spans", () => {
    expect(substitute("hello world", [], vault)).toBe("hello world");
  });

  it("replaces a single span", () => {
    const spans: Span[] = [
      { start: 5, end: 12, type: "EMAIL", score: 0.99, detector: "presidio" },
    ];
    const result = substitute("user=a@b.com end", spans, vault);
    expect(result).toBe("user=[[EMAIL_1]] end");
  });

  it("replaces multiple spans right-to-left preserving offsets", () => {
    const text = "key=AKIAIOSFODNN7EXAMPLE email=a@b.com";
    const spans: Span[] = [
      { start: 4, end: 24, type: "AWS_ACCESS_KEY", score: 0.99, detector: "regex" },
      { start: 31, end: 38, type: "EMAIL", score: 0.95, detector: "presidio" },
    ];
    const result = substitute(text, spans, vault);
    expect(result).toBe("key=[[AWS_ACCESS_KEY_1]] email=[[EMAIL_1]]");
  });

  it("reuses placeholder for same value", () => {
    const text = "first=a@b.com second=a@b.com";
    const spans: Span[] = [
      { start: 6, end: 13, type: "EMAIL", score: 0.99, detector: "presidio" },
      { start: 21, end: 28, type: "EMAIL", score: 0.99, detector: "presidio" },
    ];
    const result = substitute(text, spans, vault);
    expect(result).toBe("first=[[EMAIL_1]] second=[[EMAIL_1]]");
    expect(vault.getRedactedCount()).toBe(1);
  });

  it("handles adjacent spans", () => {
    const text = "AB";
    const spans: Span[] = [
      { start: 0, end: 1, type: "CHAR_A", score: 1, detector: "test" },
      { start: 1, end: 2, type: "CHAR_B", score: 1, detector: "test" },
    ];
    const result = substitute(text, spans, vault);
    // Right-to-left: B is processed first, then A
    expect(result).toBe("[[CHAR_A_1]][[CHAR_B_1]]");
  });

  it("handles spans given out of order", () => {
    const text = "A...B...";
    const spans: Span[] = [
      { start: 4, end: 5, type: "X", score: 1, detector: "test" },
      { start: 0, end: 1, type: "X", score: 1, detector: "test" },
    ];
    const result = substitute(text, spans, vault);
    expect(result).toContain("[[X_");
  });
});
