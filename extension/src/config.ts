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

export function loadConfig(
  _cwd: string,
  _isProjectTrusted: boolean,
): ScrubConfig {
  const config = { ...DEFAULTS };

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
