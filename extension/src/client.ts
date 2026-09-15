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

export class SanitizeUnavailableError extends Error {
  constructor(cause?: unknown) {
    super("sanitize is unavailable");
    this.name = "SanitizeUnavailableError";
    if (cause instanceof Error) this.cause = cause;
  }
}

export class SanitizeClient {
  constructor(
    private baseUrl: string,
    private timeoutMs: number,
  ) {}

  async detect(request: DetectRequest): Promise<DetectResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/v1/detect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
}
