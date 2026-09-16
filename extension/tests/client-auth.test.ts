import { describe, test, expect, vi, beforeEach } from "vitest";
import { SanitizeClient } from "../src/client.js";

describe("SanitizeClient bearer auth", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test("sends Authorization header when token is set", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          spans: [],
          stats: { ms: 1, detectors_run: [] },
          policy_version: "v1",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new SanitizeClient("http://localhost:7411", 4000, "my-token");
    await client.detect({ text: "hello" });

    const [, options] = fetchSpy.mock.calls[0];
    const headers = options!.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer my-token");
  });

  test("does not send Authorization header when token is null", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          spans: [],
          stats: { ms: 1, detectors_run: [] },
          policy_version: "v1",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new SanitizeClient("http://localhost:7411", 4000);
    await client.detect({ text: "hello" });

    const [, options] = fetchSpy.mock.calls[0];
    const headers = options!.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  test("health check does not require token", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "ok" }), { status: 200 }),
    );

    const client = new SanitizeClient("http://localhost:7411", 4000, "my-token");
    const result = await client.health();
    expect(result).toBe(true);
  });
});
