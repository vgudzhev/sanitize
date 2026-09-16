import type { Span } from "./types.js";

export interface AuditEvent {
  timestamp: string;
  event: "scrub";
  source: string;
  categories: Record<string, number>;
  total_spans: number;
  policy_version: string;
}

export class AuditEmitter {
  private url: string;
  private token: string | null;

  constructor(url: string, token: string | null = null) {
    this.url = url;
    this.token = token;
  }

  emit(spans: Span[], source: string, policyVersion: string): void {
    const categories: Record<string, number> = {};
    for (const span of spans) {
      categories[span.type] = (categories[span.type] ?? 0) + 1;
    }

    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      event: "scrub",
      source,
      categories,
      total_spans: spans.length,
      policy_version: policyVersion,
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(5000),
    }).catch(() => {
      // Fire-and-forget: audit must never block the agent
    });
  }
}
