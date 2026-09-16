import { describe, test, expect, vi, beforeEach } from "vitest";
import { AuditEmitter } from "../src/audit.js";

describe("AuditEmitter", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test("emits category counts, not content", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 }),
    );

    const emitter = new AuditEmitter("http://audit.test/events");
    emitter.emit(
      [
        { start: 0, end: 10, type: "AWS_ACCESS_KEY", score: 0.99, detector: "regex" },
        { start: 20, end: 30, type: "AWS_ACCESS_KEY", score: 0.95, detector: "regex" },
        { start: 40, end: 50, type: "EMAIL_ADDRESS", score: 0.85, detector: "presidio" },
      ],
      "tool_result",
      "2026-09-16.1",
    );

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe("http://audit.test/events");

    const body = JSON.parse(options!.body as string);
    expect(body.event).toBe("scrub");
    expect(body.source).toBe("tool_result");
    expect(body.categories.AWS_ACCESS_KEY).toBe(2);
    expect(body.categories.EMAIL_ADDRESS).toBe(1);
    expect(body.total_spans).toBe(3);
    expect(body.policy_version).toBe("2026-09-16.1");
    // Must NOT contain actual text content
    expect(JSON.stringify(body)).not.toContain("AKIA");
  });

  test("includes bearer token when configured", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", { status: 200 }),
    );

    const emitter = new AuditEmitter("http://audit.test/events", "my-token");
    emitter.emit([], "input", "v1");

    const [, options] = fetchSpy.mock.calls[0];
    const headers = options!.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer my-token");
  });

  test("does not throw on fetch failure (fire-and-forget)", () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"));

    const emitter = new AuditEmitter("http://audit.test/events");
    // This should NOT throw
    expect(() => {
      emitter.emit(
        [{ start: 0, end: 5, type: "TEST", score: 0.9, detector: "test" }],
        "input",
        "v1",
      );
    }).not.toThrow();
  });
});
