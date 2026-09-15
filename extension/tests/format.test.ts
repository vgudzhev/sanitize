import { describe, it, expect } from "vitest";
import { formatPlaceholder } from "../src/format.js";
import { Vault } from "../src/vault.js";

describe("formatPlaceholder", () => {
  it("formats EMAIL as user@redacted.example", () => {
    expect(formatPlaceholder("EMAIL", 1)).toBe("user1@redacted.example");
    expect(formatPlaceholder("EMAIL", 3)).toBe("user3@redacted.example");
  });

  it("formats IP_ADDRESS as 10.0.x.x", () => {
    expect(formatPlaceholder("IP_ADDRESS", 1)).toBe("10.0.0.1");
    expect(formatPlaceholder("IP_ADDRESS", 256)).toBe("10.0.1.0");
  });

  it("formats PHONE_NUMBER", () => {
    expect(formatPlaceholder("PHONE_NUMBER", 1)).toBe("555-000-0001");
  });

  it("formats CREDIT_CARD", () => {
    expect(formatPlaceholder("CREDIT_CARD", 1)).toBe("4000-0000-0000-0001");
  });

  it("formats AWS_ACCESS_KEY with correct length", () => {
    const key = formatPlaceholder("AWS_ACCESS_KEY", 1);
    expect(key).toMatch(/^AKIA0+1$/);
    expect(key).toHaveLength(20);
  });

  it("formats PERSON", () => {
    expect(formatPlaceholder("PERSON", 2)).toBe("Person_2");
  });

  it("formats DB_CONNECTION_URL", () => {
    const url = formatPlaceholder("DB_CONNECTION_URL", 1);
    expect(url).toContain("redacted.example");
    expect(url).toContain("postgres://");
  });

  it("falls back to bracket style for unknown types", () => {
    expect(formatPlaceholder("WEIRD_TYPE", 5)).toBe("[[WEIRD_TYPE_5]]");
  });
});

describe("Vault format-preserving mode", () => {
  it("produces format-preserving placeholders when enabled", () => {
    const vault = new Vault(true);
    const p = vault.getPlaceholder("a@b.com", "EMAIL");
    expect(p).toBe("user1@redacted.example");
  });

  it("produces bracket placeholders when disabled", () => {
    const vault = new Vault(false);
    const p = vault.getPlaceholder("a@b.com", "EMAIL");
    expect(p).toBe("[[EMAIL_1]]");
  });

  it("rehydrates format-preserving placeholders", () => {
    const vault = new Vault(true);
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("10.1.2.3", "IP_ADDRESS");
    const text = "Send to user1@redacted.example at 10.0.0.1";
    expect(vault.rehydrate(text)).toBe("Send to a@b.com at 10.1.2.3");
  });

  it("returns same placeholder for same value", () => {
    const vault = new Vault(true);
    const p1 = vault.getPlaceholder("a@b.com", "EMAIL");
    const p2 = vault.getPlaceholder("a@b.com", "EMAIL");
    expect(p1).toBe(p2);
    expect(vault.getRedactedCount()).toBe(1);
  });

  it("revealValue works in format-preserving mode", () => {
    const vault = new Vault(true);
    vault.getPlaceholder("a@b.com", "EMAIL");
    expect(vault.revealValue("user1@redacted.example")).toBe("a@b.com");
  });

  it("getRawValues works in format-preserving mode", () => {
    const vault = new Vault(true);
    vault.getPlaceholder("a@b.com", "EMAIL");
    expect(vault.getRawValues()).toContain("a@b.com");
  });
});
