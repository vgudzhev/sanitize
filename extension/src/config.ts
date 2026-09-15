export interface ScrubConfig {
  sanitize: { url: string; timeout_ms: number };
  placeholders: { open: string; close: string };
  deny_paths: string[];
  allow: string[];
}

const DEFAULTS: ScrubConfig = {
  sanitize: {
    url: "http://127.0.0.1:7411",
    timeout_ms: 4000,
  },
  placeholders: { open: "[[", close: "]]" },
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
};

export function loadConfig(
  _cwd: string,
  _isProjectTrusted: boolean,
): ScrubConfig {
  return { ...DEFAULTS };
}
