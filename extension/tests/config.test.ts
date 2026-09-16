import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  loadConfig,
  loadProjectArrays,
  applyProjectArrays,
} from "../src/config.js";
import type { ScrubConfig } from "../src/config.js";

describe("loadConfig — YAML loading", () => {
  let tmpHome: string;
  let tmpProject: string;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    tmpHome = mkdtempSync(join(tmpdir(), "pi-scrub-home-"));
    tmpProject = mkdtempSync(join(tmpdir(), "pi-scrub-proj-"));

    for (const key of [
      "SANITIZE_URL",
      "SANITIZE_TOKEN",
      "SANITIZE_POLICY_URL",
      "SANITIZE_AUDIT_URL",
      "SANITIZE_PUBLIC_KEY",
    ]) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) delete process.env[key];
      else process.env[key] = val;
    }
    rmSync(tmpHome, { recursive: true, force: true });
    rmSync(tmpProject, { recursive: true, force: true });
  });

  it("returns defaults when no YAML files exist", () => {
    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://127.0.0.1:7411");
    expect(config.sanitize.timeout_ms).toBe(4000);
    expect(config.deny_paths).toContain("~/.ssh/**");
    expect(config.allow).toContain("127.0.0.1");
  });

  it("deep-copies defaults so mutations do not leak between calls", () => {
    const a = loadConfig(tmpProject, tmpHome);
    a.deny_paths.push("LEAKED");
    const b = loadConfig(tmpProject, tmpHome);
    expect(b.deny_paths).not.toContain("LEAKED");
  });

  it("loads global config from ~/.claude/sanitize.yaml", () => {
    const globalDir = join(tmpHome, ".claude");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      "sanitize:\n  url: http://custom-host:9999\n  timeout_ms: 8000\n",
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://custom-host:9999");
    expect(config.sanitize.timeout_ms).toBe(8000);
  });

  it("falls back to ~/.pi/agent/sanitize.yaml when ~/.claude/ absent", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      "sanitize:\n  url: http://pi-host:7411\n",
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://pi-host:7411");
  });

  it("prefers ~/.claude/ over ~/.pi/agent/ when both exist", () => {
    const claudeDir = join(tmpHome, ".claude");
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(
      join(claudeDir, "sanitize.yaml"),
      "sanitize:\n  url: http://claude-host:7411\n",
    );
    const piDir = join(tmpHome, ".pi", "agent");
    mkdirSync(piDir, { recursive: true });
    writeFileSync(
      join(piDir, "sanitize.yaml"),
      "sanitize:\n  url: http://pi-host:7411\n",
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://claude-host:7411");
  });

  it("merges deny_paths additively from global config", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      'deny_paths:\n  - "~/.custom-secrets/**"\n',
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.deny_paths).toContain("~/.ssh/**");
    expect(config.deny_paths).toContain("~/.custom-secrets/**");
  });

  it("env vars override YAML config", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      "sanitize:\n  url: http://yaml-host:7411\n",
    );

    process.env.SANITIZE_URL = "http://env-host:7411";
    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://env-host:7411");
  });

  it("does not duplicate allow entries already in defaults", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      'allow:\n  - "127.0.0.1"\n  - "internal.corp"\n',
    );

    const config = loadConfig(tmpProject, tmpHome);
    const count = config.allow.filter((a) => a === "127.0.0.1").length;
    expect(count).toBe(1);
    expect(config.allow).toContain("internal.corp");
  });

  it("handles malformed YAML gracefully", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(join(globalDir, "sanitize.yaml"), ": not valid yaml [");

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.sanitize.url).toBe("http://127.0.0.1:7411");
  });

  it("loads org config from YAML", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      "org:\n  policy_url: https://org.example/policy\n  token: org-token-123\n",
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.org.policy_url).toBe("https://org.example/policy");
    expect(config.org.token).toBe("org-token-123");
  });

  it("merges placeholders.format_preserving only (open/close ignored)", () => {
    const globalDir = join(tmpHome, ".pi", "agent");
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(
      join(globalDir, "sanitize.yaml"),
      "placeholders:\n  format_preserving: true\n  open: '<<'\n",
    );

    const config = loadConfig(tmpProject, tmpHome);
    expect(config.placeholders.format_preserving).toBe(true);
    expect(config.placeholders.open).toBe("[[");
    expect(config.placeholders.close).toBe("]]");
  });
});

describe("loadProjectArrays", () => {
  let tmpProject: string;

  beforeEach(() => {
    tmpProject = mkdtempSync(join(tmpdir(), "pi-scrub-proj-"));
  });

  afterEach(() => {
    rmSync(tmpProject, { recursive: true, force: true });
  });

  it("returns null when no project YAML exists", () => {
    expect(loadProjectArrays(tmpProject)).toBeNull();
  });

  it("returns deny_paths and allow arrays from .claude/sanitize.yaml", () => {
    const projDir = join(tmpProject, ".claude");
    mkdirSync(projDir, { recursive: true });
    writeFileSync(
      join(projDir, "sanitize.yaml"),
      'deny_paths:\n  - "**/secrets.json"\nallow:\n  - "staging.internal"\n',
    );

    const arrays = loadProjectArrays(tmpProject);
    expect(arrays).not.toBeNull();
    expect(arrays!.deny_paths).toEqual(["**/secrets.json"]);
    expect(arrays!.allow).toEqual(["staging.internal"]);
  });

  it("falls back to .pi/sanitize.yaml when .claude/ absent", () => {
    const projDir = join(tmpProject, ".pi");
    mkdirSync(projDir, { recursive: true });
    writeFileSync(
      join(projDir, "sanitize.yaml"),
      'deny_paths:\n  - "**/legacy.json"\n',
    );

    const arrays = loadProjectArrays(tmpProject);
    expect(arrays).not.toBeNull();
    expect(arrays!.deny_paths).toEqual(["**/legacy.json"]);
  });

  it("ignores scalar fields in project YAML", () => {
    const projDir = join(tmpProject, ".pi");
    mkdirSync(projDir, { recursive: true });
    writeFileSync(
      join(projDir, "sanitize.yaml"),
      'sanitize:\n  url: http://evil:9999\norg:\n  token: hijacked\ndeny_paths:\n  - "safe-path"\n',
    );

    const arrays = loadProjectArrays(tmpProject);
    expect(arrays!.deny_paths).toEqual(["safe-path"]);
    expect(arrays!.allow).toEqual([]);
    expect((arrays as any).sanitize).toBeUndefined();
    expect((arrays as any).org).toBeUndefined();
  });
});

describe("applyProjectArrays", () => {
  it("unions arrays into config without duplicates", () => {
    const config: ScrubConfig = {
      sanitize: { url: "http://127.0.0.1:7411", timeout_ms: 4000 },
      placeholders: { open: "[[", close: "]]", format_preserving: false },
      deny_paths: ["~/.ssh/**", "**/.env*"],
      allow: ["127.0.0.1"],
      org: {
        policy_url: null,
        token: null,
        audit_url: null,
        public_key: null,
      },
    };

    applyProjectArrays(config, {
      deny_paths: ["**/.env*", "**/secrets.json"],
      allow: ["127.0.0.1", "staging.internal"],
    });

    expect(config.deny_paths).toEqual([
      "~/.ssh/**",
      "**/.env*",
      "**/secrets.json",
    ]);
    expect(config.allow).toEqual(["127.0.0.1", "staging.internal"]);
  });

  it("project deny_paths adds to both defaults and global", () => {
    const config: ScrubConfig = {
      sanitize: { url: "http://127.0.0.1:7411", timeout_ms: 4000 },
      placeholders: { open: "[[", close: "]]", format_preserving: false },
      deny_paths: ["~/.ssh/**", "~/.global-secret"],
      allow: ["127.0.0.1"],
      org: {
        policy_url: null,
        token: null,
        audit_url: null,
        public_key: null,
      },
    };

    applyProjectArrays(config, {
      deny_paths: ["~/.project-secret"],
      allow: [],
    });

    expect(config.deny_paths).toContain("~/.ssh/**");
    expect(config.deny_paths).toContain("~/.global-secret");
    expect(config.deny_paths).toContain("~/.project-secret");
  });
});
