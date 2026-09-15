import { describe, it, expect } from "vitest";
import { isDeniedPath } from "../src/denylist.js";

const HOME = "/Users/testuser";

describe("isDeniedPath", () => {
  it("denies ~/.ssh/id_rsa", () => {
    expect(isDeniedPath("/Users/testuser/.ssh/id_rsa", HOME)).toBe(true);
  });

  it("denies ~/.ssh/config", () => {
    expect(isDeniedPath("/Users/testuser/.ssh/config", HOME)).toBe(true);
  });

  it("denies .env in any directory", () => {
    expect(isDeniedPath("/project/.env", HOME)).toBe(true);
  });

  it("denies .env.local in any directory", () => {
    expect(isDeniedPath("/project/.env.local", HOME)).toBe(true);
  });

  it("denies *.pem files", () => {
    expect(isDeniedPath("/some/path/cert.pem", HOME)).toBe(true);
  });

  it("denies *.key files", () => {
    expect(isDeniedPath("/some/path/server.key", HOME)).toBe(true);
  });

  it("denies ~/.aws/credentials", () => {
    expect(isDeniedPath("/Users/testuser/.aws/credentials", HOME)).toBe(true);
  });

  it("denies ~/.kube/config", () => {
    expect(isDeniedPath("/Users/testuser/.kube/config", HOME)).toBe(true);
  });

  it("denies *.tfstate files", () => {
    expect(isDeniedPath("/infra/terraform.tfstate", HOME)).toBe(true);
  });

  it("allows normal source files", () => {
    expect(isDeniedPath("/project/src/index.ts", HOME)).toBe(false);
  });

  it("allows normal config files", () => {
    expect(isDeniedPath("/project/tsconfig.json", HOME)).toBe(false);
  });

  it("allows README", () => {
    expect(isDeniedPath("/project/README.md", HOME)).toBe(false);
  });

  it("supports extra patterns", () => {
    expect(
      isDeniedPath("/project/secrets.yaml", HOME, ["**/secrets.yaml"]),
    ).toBe(true);
  });
});
