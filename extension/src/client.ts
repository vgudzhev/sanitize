import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { Span } from "./types.js";

export interface DetectRequest {
  text: string;
  hints?: { source?: string; tool?: string; path?: string };
  policy?: string;
}

export interface DetectResponse {
  spans: Span[];
  stats: { ms: number; detectors_run: string[] };
  policy_version: string;
}

export interface PolicyResponse {
  policy: Record<string, unknown>;
  policy_version: string;
  signature?: string;
  key_id?: string;
}

export class SanitizeUnavailableError extends Error {
  constructor(cause?: unknown) {
    super("sanitize is unavailable");
    this.name = "SanitizeUnavailableError";
    if (cause instanceof Error) this.cause = cause;
  }
}

export class PolicyVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyVerificationError";
  }
}

export class SanitizeClient {
  constructor(
    private baseUrl: string,
    private timeoutMs: number,
    private token: string | null = null,
  ) {}

  private _headers(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    return headers;
  }

  async detect(request: DetectRequest): Promise<DetectResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/v1/detect`, {
        method: "POST",
        headers: this._headers(),
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new SanitizeUnavailableError(
          new Error(`HTTP ${response.status}`),
        );
      }

      return (await response.json()) as DetectResponse;
    } catch (e) {
      if (e instanceof SanitizeUnavailableError) throw e;
      throw new SanitizeUnavailableError(e);
    } finally {
      clearTimeout(timer);
    }
  }

  async health(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2000);
      try {
        const response = await fetch(`${this.baseUrl}/v1/health`, {
          signal: controller.signal,
        });
        return response.ok;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return false;
    }
  }

  async fetchPolicy(publicKeyPem: string | null): Promise<PolicyResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/v1/policy`, {
        headers: this._headers(),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new SanitizeUnavailableError(
          new Error(`HTTP ${response.status}`),
        );
      }

      const data = (await response.json()) as PolicyResponse;

      if (publicKeyPem && data.signature) {
        const canonicalJson = canonicalStringify(data.policy);
        const verified = verifyEd25519(
          publicKeyPem,
          Buffer.from(canonicalJson),
          Buffer.from(data.signature, "hex"),
        );
        if (!verified) {
          throw new PolicyVerificationError(
            "Policy signature verification failed",
          );
        }
      }

      return data;
    } catch (e) {
      if (
        e instanceof SanitizeUnavailableError ||
        e instanceof PolicyVerificationError
      )
        throw e;
      throw new SanitizeUnavailableError(e);
    } finally {
      clearTimeout(timer);
    }
  }
}

function canonicalStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = keys.map(
    (k) =>
      JSON.stringify(k) +
      ":" +
      canonicalStringify((obj as Record<string, unknown>)[k]),
  );
  return "{" + pairs.join(",") + "}";
}

function verifyEd25519(
  publicKeyPem: string,
  data: Buffer,
  signature: Buffer,
): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return cryptoVerify(null, data, key, signature);
  } catch {
    return false;
  }
}
