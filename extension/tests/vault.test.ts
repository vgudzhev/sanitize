import { describe, it, expect, beforeEach } from "vitest";
import { Vault } from "../src/vault.js";

describe("Vault", () => {
  let vault: Vault;

  beforeEach(() => {
    vault = new Vault();
  });

  it("mints a placeholder on first encounter", () => {
    const p = vault.getPlaceholder("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY");
    expect(p).toBe("[[AWS_ACCESS_KEY_1]]");
  });

  it("returns same placeholder for same value", () => {
    const p1 = vault.getPlaceholder("secret-val", "TOKEN");
    const p2 = vault.getPlaceholder("secret-val", "TOKEN");
    expect(p1).toBe(p2);
    expect(vault.getRedactedCount()).toBe(1);
  });

  it("increments counter per type", () => {
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("x@y.com", "EMAIL");
    const p3 = vault.getPlaceholder("z@w.com", "EMAIL");
    expect(p3).toBe("[[EMAIL_3]]");
    expect(vault.getRedactedCount()).toBe(3);
  });

  it("tracks counters independently per type", () => {
    vault.getPlaceholder("10.0.0.1", "IP");
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("10.0.0.2", "IP");
    expect(vault.getPlaceholder("10.0.0.2", "IP")).toBe("[[IP_2]]");
  });

  it("rehydrates placeholders to real values", () => {
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("10.0.0.1", "IP");
    const result = vault.rehydrate("Send to [[EMAIL_1]] at [[IP_1]]");
    expect(result).toBe("Send to a@b.com at 10.0.0.1");
  });

  it("leaves unknown placeholders untouched", () => {
    const result = vault.rehydrate("Check [[UNKNOWN_99]]");
    expect(result).toBe("Check [[UNKNOWN_99]]");
  });

  it("lists placeholders with types but not values", () => {
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("some-key", "AWS_ACCESS_KEY");
    const list = vault.listPlaceholders();
    expect(list).toEqual([
      { placeholder: "[[EMAIL_1]]", type: "EMAIL" },
      { placeholder: "[[AWS_ACCESS_KEY_1]]", type: "AWS_ACCESS_KEY" },
    ]);
  });

  it("clears all state", () => {
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.clear();
    expect(vault.getRedactedCount()).toBe(0);
    expect(vault.listPlaceholders()).toEqual([]);
    const p = vault.getPlaceholder("a@b.com", "EMAIL");
    expect(p).toBe("[[EMAIL_1]]");
  });

  it("handles rehydration of text with no placeholders", () => {
    vault.getPlaceholder("a@b.com", "EMAIL");
    const result = vault.rehydrate("No placeholders here");
    expect(result).toBe("No placeholders here");
  });

  describe("revealValue", () => {
    it("returns raw value for known placeholder", () => {
      vault.getPlaceholder("a@b.com", "EMAIL");
      expect(vault.revealValue("[[EMAIL_1]]")).toBe("a@b.com");
    });

    it("returns (unknown) for unknown placeholder", () => {
      expect(vault.revealValue("[[NOPE_99]]")).toBe("(unknown)");
    });
  });

  describe("getRawValues", () => {
    it("returns empty array when vault is empty", () => {
      expect(vault.getRawValues()).toEqual([]);
    });

    it("returns all raw values stored in vault", () => {
      vault.getPlaceholder("a@b.com", "EMAIL");
      vault.getPlaceholder("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY");
      const values = vault.getRawValues();
      expect(values).toContain("a@b.com");
      expect(values).toContain("AKIAIOSFODNN7EXAMPLE");
      expect(values).toHaveLength(2);
    });

    it("does not include duplicates", () => {
      vault.getPlaceholder("a@b.com", "EMAIL");
      vault.getPlaceholder("a@b.com", "EMAIL");
      expect(vault.getRawValues()).toHaveLength(1);
    });
  });

  describe("restoreFrom", () => {
    it("mutates vault in place so existing references see restored data", () => {
      const ref = vault;
      vault.restoreFrom({
        forward: { "[[EMAIL_1]]": "a@b.com" },
        counters: { EMAIL: 1 },
        redactedCount: 1,
        formatPreserving: false,
      });
      expect(ref.getRedactedCount()).toBe(1);
      expect(ref.revealValue("[[EMAIL_1]]")).toBe("a@b.com");
      expect(ref.rehydrate("Send to [[EMAIL_1]]")).toBe("Send to a@b.com");
    });

    it("continues counter numbering after restore", () => {
      vault.restoreFrom({
        forward: { "[[EMAIL_1]]": "a@b.com" },
        counters: { EMAIL: 1 },
        redactedCount: 1,
        formatPreserving: false,
      });
      const p = vault.getPlaceholder("z@w.com", "EMAIL");
      expect(p).toBe("[[EMAIL_2]]");
    });
  });
});
