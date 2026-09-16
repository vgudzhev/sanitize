import { describe, test, expect, vi, afterEach } from "vitest";
import { loadConfig } from "../src/config.js";

describe("loadConfig org features", () => {
  const origEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...origEnv };
  });

  test("defaults have null org fields", () => {
    const config = loadConfig("/tmp", false);
    expect(config.org.policy_url).toBeNull();
    expect(config.org.token).toBeNull();
    expect(config.org.audit_url).toBeNull();
    expect(config.org.public_key).toBeNull();
  });

  test("reads SANITIZE_TOKEN from env", () => {
    process.env.SANITIZE_TOKEN = "secret-123";
    const config = loadConfig("/tmp", false);
    expect(config.org.token).toBe("secret-123");
  });

  test("reads SANITIZE_URL from env", () => {
    process.env.SANITIZE_URL = "https://sanitize.corp.internal:7411";
    const config = loadConfig("/tmp", false);
    expect(config.sanitize.url).toBe("https://sanitize.corp.internal:7411");
  });

  test("reads SANITIZE_POLICY_URL from env", () => {
    process.env.SANITIZE_POLICY_URL = "https://sanitize.corp.internal:7411";
    const config = loadConfig("/tmp", false);
    expect(config.org.policy_url).toBe("https://sanitize.corp.internal:7411");
  });

  test("reads SANITIZE_AUDIT_URL from env", () => {
    process.env.SANITIZE_AUDIT_URL = "https://audit.corp.internal/events";
    const config = loadConfig("/tmp", false);
    expect(config.org.audit_url).toBe("https://audit.corp.internal/events");
  });

  test("reads SANITIZE_PUBLIC_KEY from env", () => {
    process.env.SANITIZE_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMCo...\n-----END PUBLIC KEY-----";
    const config = loadConfig("/tmp", false);
    expect(config.org.public_key).toContain("BEGIN PUBLIC KEY");
  });
});
