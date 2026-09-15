const FORMATS: Record<string, (n: number) => string> = {
  EMAIL: (n) => `user${n}@redacted.example`,
  PHONE_NUMBER: (n) => `555-000-${String(n).padStart(4, "0")}`,
  IP_ADDRESS: (n) => `10.0.${Math.floor(n / 256) % 256}.${n % 256}`,
  CREDIT_CARD: (n) => `4000-0000-0000-${String(n).padStart(4, "0")}`,
  AWS_ACCESS_KEY: (n) =>
    `AKIA${"0".repeat(16 - String(n).length)}${n}`,
  PERSON: (n) => `Person_${n}`,
  ORGANIZATION: (n) => `Org_${n}`,
  ADDRESS: (n) => `${n} Redacted St, Anytown, XX 00000`,
  URL: (n) => `https://redacted.example/path/${n}`,
  DB_CONNECTION_URL: (n) =>
    `postgres://user${n}:pass@redacted.example:5432/db${n}`,
  PRIVATE_KEY: (n) => `[PRIVATE_KEY_${n}_REDACTED]`,
  GENERIC_SECRET: (n) => `REDACTED_SECRET_${n}`,
  GITHUB_TOKEN: (n) => `ghp_${"0".repeat(36 - String(n).length)}${n}`,
  JWT: (n) => `eyJ_REDACTED_${n}`,
  STRIPE_KEY: (n) => `sk_test_${"0".repeat(24 - String(n).length)}${n}`,
  INTERNAL_HOSTNAME: (n) => `host${n}.redacted.internal`,
  PROJECT_CODENAME: (n) => `Project_${n}`,
};

export function formatPlaceholder(type: string, counter: number): string {
  const formatter = FORMATS[type];
  if (formatter) return formatter(counter);
  return `[[${type}_${counter}]]`;
}
