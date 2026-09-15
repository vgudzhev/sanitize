interface EgressCheck {
  name: string;
  pattern: RegExp;
}

const CHECKS: EgressCheck[] = [
  {
    name: "PRIVATE_KEY",
    pattern: /-----BEGIN\s[A-Z ]*PRIVATE KEY-----/,
  },
  {
    name: "AWS_ACCESS_KEY",
    pattern: /(?<!\[\[)(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?!\w*\]\])/,
  },
  {
    name: "GITHUB_TOKEN",
    pattern: /(?<!\[\[)gh[pousr]_[A-Za-z0-9_]{36,}(?!\w*\]\])/,
  },
  {
    name: "SLACK_TOKEN",
    pattern: /(?<!\[\[)xox[bpoas]-[A-Za-z0-9-]+(?!\w*\]\])/,
  },
  {
    name: "JWT",
    pattern: /(?<!\[\[)eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+(?!\w*\]\])/,
  },
  {
    name: "DB_URL_WITH_CREDENTIALS",
    pattern:
      /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:]+:[^@]+@/,
  },
  {
    name: "BEARER_TOKEN",
    pattern: /(?:Bearer|Authorization:?\s*Bearer)\s+[A-Za-z0-9_\-.~+/]{20,}/i,
  },
  {
    name: "GENERIC_SECRET_ASSIGNMENT",
    pattern:
      /(?:password|passwd|pwd|secret_access_key|secret|token|api_key|apikey|api-key|access_key|auth_token|client_secret)\s*[=:]\s*['"]?[A-Za-z0-9_\-./+=]{16,}/i,
  },
];

const FORMAT_PRESERVING_SAFE: RegExp[] = [
  /ghp_0{30,}\d+/,
  /postgres:\/\/user\d+:pass@redacted\.example:5432\/db\d+/,
  /sk_test_0{18,}\d+/,
];

function isFormatPreservingFake(payload: string, match: RegExpMatchArray): boolean {
  const text = match[0];
  return FORMAT_PRESERVING_SAFE.some((p) => p.test(text));
}

export function verifyEgress(payload: string): {
  safe: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  for (const check of CHECKS) {
    const match = check.pattern.exec(payload);
    if (match && !isFormatPreservingFake(payload, match)) {
      violations.push(check.name);
    }
  }

  return { safe: violations.length === 0, violations };
}
