import { describe, it, expect } from "vitest";
import { verifyEgress } from "../src/egress.js";

describe("verifyEgress", () => {
  it("passes clean text", () => {
    const result = verifyEgress('{"messages": [{"text": "hello world"}]}');
    expect(result.safe).toBe(true);
    expect(result.violations).toEqual([]);
  });

  it("catches AWS access key", () => {
    const result = verifyEgress("key=AKIAIOSFODNN7EXAMPLE");
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("AWS_ACCESS_KEY");
  });

  it("does NOT flag placeholder [[AWS_ACCESS_KEY_1]]", () => {
    const result = verifyEgress(
      '{"text": "credential is [[AWS_ACCESS_KEY_1]]"}',
    );
    expect(result.safe).toBe(true);
  });

  it("catches private key header", () => {
    const result = verifyEgress(
      "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("PRIVATE_KEY");
  });

  it("catches GitHub token", () => {
    const result = verifyEgress(
      "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("GITHUB_TOKEN");
  });

  it("does NOT flag [[GITHUB_TOKEN_1]] placeholder", () => {
    const result = verifyEgress('{"token": "[[GITHUB_TOKEN_1]]"}');
    expect(result.safe).toBe(true);
  });

  it("catches Slack token", () => {
    const result = verifyEgress("xoxb-123456-abcdef");
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("SLACK_TOKEN");
  });

  it("catches JWT", () => {
    const result = verifyEgress(
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("JWT");
  });

  it("catches DB URL with credentials", () => {
    const result = verifyEgress(
      "postgres://admin:supersecret@db.internal:5432/prod",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("DB_URL_WITH_CREDENTIALS");
  });

  it("catches Bearer token", () => {
    const result = verifyEgress(
      "Authorization: Bearer sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXX",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("BEARER_TOKEN");
  });

  it("catches secret_access_key assignment", () => {
    const result = verifyEgress(
      "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );
    expect(result.safe).toBe(false);
    expect(result.violations).toContain("GENERIC_SECRET_ASSIGNMENT");
  });

  it("catches each §6 item individually", () => {
    const dbUrl = verifyEgress(
      "postgres://admin:s3cr3tP4ss@db.internal:5432/myapp",
    );
    expect(dbUrl.safe).toBe(false);
    expect(dbUrl.violations).toContain("DB_URL_WITH_CREDENTIALS");

    const awsKey = verifyEgress("access_key_id: AKIAIOSFODNN7EXAMPLE");
    expect(awsKey.safe).toBe(false);
    expect(awsKey.violations).toContain("AWS_ACCESS_KEY");

    const awsSecret = verifyEgress(
      "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    );
    expect(awsSecret.safe).toBe(false);

    const pem = verifyEgress("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
    expect(pem.safe).toBe(false);
    expect(pem.violations).toContain("PRIVATE_KEY");
  });

  it("reports multiple violations", () => {
    const result = verifyEgress(
      "key=AKIAIOSFODNN7EXAMPLE -----BEGIN RSA PRIVATE KEY-----",
    );
    expect(result.safe).toBe(false);
    expect(result.violations.length).toBeGreaterThanOrEqual(2);
  });
});
