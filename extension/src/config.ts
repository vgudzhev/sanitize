import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { load as yamlLoad } from "js-yaml";

export interface OrgConfig {
  policy_url: string | null;
  token: string | null;
  audit_url: string | null;
  public_key: string | null;
}

export interface ScrubConfig {
  sanitize: { url: string; timeout_ms: number };
  placeholders: { open: string; close: string; format_preserving: boolean };
  deny_paths: string[];
  allow: string[];
  org: OrgConfig;
}

const DEFAULTS: ScrubConfig = {
  sanitize: {
    url: "http://127.0.0.1:7411",
    timeout_ms: 4000,
  },
  placeholders: { open: "[[", close: "]]", format_preserving: false },
  deny_paths: [
    "~/.ssh/**",
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "~/.aws/credentials",
    "~/.kube/config",
    "~/.netrc",
    "**/*.ovpn",
    "**/*.tfstate",
  ],
  allow: ["127.0.0.1", "example.com"],
  org: {
    policy_url: null,
    token: null,
    audit_url: null,
    public_key: null,
  },
};

interface RawYaml {
  sanitize?: { url?: string; timeout_ms?: number };
  placeholders?: { format_preserving?: boolean };
  deny_paths?: string[];
  allow?: string[];
  org?: {
    policy_url?: string;
    token?: string;
    audit_url?: string;
    public_key?: string;
  };
}

function readYamlFile(path: string): RawYaml | null {
  if (!existsSync(path)) return null;
  try {
    const content = readFileSync(path, "utf-8");
    const parsed = yamlLoad(content);
    if (parsed === null || typeof parsed !== "object") return null;
    return parsed as RawYaml;
  } catch {
    return null;
  }
}

function mergeLayer(base: ScrubConfig, layer: RawYaml): ScrubConfig {
  const result = { ...base };

  if (layer.sanitize) {
    result.sanitize = { ...result.sanitize };
    if (typeof layer.sanitize.url === "string")
      result.sanitize.url = layer.sanitize.url;
    if (typeof layer.sanitize.timeout_ms === "number")
      result.sanitize.timeout_ms = layer.sanitize.timeout_ms;
  }

  if (layer.placeholders) {
    result.placeholders = { ...result.placeholders };
    if (typeof layer.placeholders.format_preserving === "boolean")
      result.placeholders.format_preserving =
        layer.placeholders.format_preserving;
  }

  if (Array.isArray(layer.deny_paths)) {
    const existing = new Set(result.deny_paths);
    for (const p of layer.deny_paths) {
      if (typeof p === "string" && !existing.has(p)) {
        result.deny_paths = [...result.deny_paths, p];
        existing.add(p);
      }
    }
  }

  if (Array.isArray(layer.allow)) {
    const existing = new Set(result.allow);
    for (const a of layer.allow) {
      if (typeof a === "string" && !existing.has(a)) {
        result.allow = [...result.allow, a];
        existing.add(a);
      }
    }
  }

  if (layer.org) {
    result.org = { ...result.org };
    if (typeof layer.org.policy_url === "string")
      result.org.policy_url = layer.org.policy_url;
    if (typeof layer.org.token === "string")
      result.org.token = layer.org.token;
    if (typeof layer.org.audit_url === "string")
      result.org.audit_url = layer.org.audit_url;
    if (typeof layer.org.public_key === "string")
      result.org.public_key = layer.org.public_key;
  }

  return result;
}

export function loadConfig(cwd: string, home?: string): ScrubConfig {
  const config = structuredClone(DEFAULTS);
  const h = home ?? homedir();

  const candidates = [
    join(h, ".claude", "sanitize.yaml"),
    join(h, ".pi", "agent", "sanitize.yaml"),
  ];
  for (const candidate of candidates) {
    const yaml = readYamlFile(candidate);
    if (yaml) return applyEnvOverrides(mergeLayer(config, yaml));
  }

  return applyEnvOverrides(config);
}

export function loadProjectArrays(
  cwd: string,
): { deny_paths: string[]; allow: string[] } | null {
  const yaml =
    readYamlFile(join(cwd, ".claude", "sanitize.yaml")) ??
    readYamlFile(join(cwd, ".pi", "sanitize.yaml"));
  if (!yaml) return null;
  return {
    deny_paths: Array.isArray(yaml.deny_paths)
      ? yaml.deny_paths.filter((p): p is string => typeof p === "string")
      : [],
    allow: Array.isArray(yaml.allow)
      ? yaml.allow.filter((a): a is string => typeof a === "string")
      : [],
  };
}

export function applyProjectArrays(
  config: ScrubConfig,
  arrays: { deny_paths: string[]; allow: string[] },
): void {
  const existingDeny = new Set(config.deny_paths);
  for (const p of arrays.deny_paths) {
    if (!existingDeny.has(p)) {
      config.deny_paths.push(p);
      existingDeny.add(p);
    }
  }
  const existingAllow = new Set(config.allow);
  for (const a of arrays.allow) {
    if (!existingAllow.has(a)) {
      config.allow.push(a);
      existingAllow.add(a);
    }
  }
}

function applyEnvOverrides(config: ScrubConfig): ScrubConfig {
  const envUrl = process.env.SANITIZE_URL;
  if (envUrl) config.sanitize = { ...config.sanitize, url: envUrl };

  const envToken = process.env.SANITIZE_TOKEN;
  if (envToken) config.org = { ...config.org, token: envToken };

  const envPolicyUrl = process.env.SANITIZE_POLICY_URL;
  if (envPolicyUrl) config.org = { ...config.org, policy_url: envPolicyUrl };

  const envAuditUrl = process.env.SANITIZE_AUDIT_URL;
  if (envAuditUrl) config.org = { ...config.org, audit_url: envAuditUrl };

  const envPubKey = process.env.SANITIZE_PUBLIC_KEY;
  if (envPubKey) config.org = { ...config.org, public_key: envPubKey };

  return config;
}
