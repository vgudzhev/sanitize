/**
 * §3.3 defense-in-depth hooks: context, message_end, session_before_compact,
 * model_select.
 *
 * Mirrors the mock setup in integration.test.ts: the sanitize client is a
 * regex mock, config is static, and a fake ExtensionAPI captures handlers.
 */
import { describe, test, expect, vi, beforeEach } from "vitest";

vi.mock("../src/client.js", () => {
  class MockClient {
    async detect(req: { text: string }) {
      const spans: Array<{
        start: number;
        end: number;
        type: string;
        score: number;
        detector: string;
      }> = [];
      const patterns: Array<{ regex: RegExp; type: string }> = [
        { regex: /AKIA[A-Z0-9]{16}/g, type: "AWS_ACCESS_KEY" },
        // Deliberately short (4 chars) so tests can seed a sub-threshold
        // vault value.
        { regex: /(?<=pin=)\d{4}/g, type: "PIN" },
      ];
      for (const { regex, type } of patterns) {
        let match;
        while ((match = regex.exec(req.text)) !== null) {
          spans.push({
            start: match.index,
            end: match.index + match[0].length,
            type,
            score: 0.95,
            detector: "mock",
          });
        }
      }
      return {
        spans,
        stats: { ms: 1, detectors_run: ["mock"] },
        policy_version: "test",
      };
    }
    async health() {
      return true;
    }
  }
  return {
    SanitizeClient: MockClient,
    SanitizeUnavailableError: class extends Error {
      constructor() {
        super("sanitize is unavailable");
        this.name = "SanitizeUnavailableError";
      }
    },
    PolicyVerificationError: class extends Error {},
  };
});

vi.mock("../src/config.js", () => ({
  loadConfig: () => ({
    sanitize: { url: "http://localhost:7411", timeout_ms: 4000 },
    deny_paths: [],
    allow: [],
    org: { policy_url: null, token: null, audit_url: null, public_key: null },
  }),
  loadProjectArrays: () => null,
  applyProjectArrays: () => {},
}));

vi.mock("../src/vault-persistence.js", () => ({
  saveVault: () => {},
  loadVault: () => null,
  deleteVaultFile: () => {},
}));

vi.mock("node:os", () => ({
  homedir: () => "/home/testuser",
}));

import type {
  ExtensionAPI,
  ExtensionContext,
  ContextEvent,
  ContextEventResult,
  ContextMessage,
  MessageEndEvent,
  SessionBeforeCompactEvent,
  SessionBeforeCompactEventResult,
  ModelSelectEvent,
  ToolResultEvent,
  ToolResultEventResult,
} from "../src/types.js";

type HandlerFn = (...args: unknown[]) => unknown;

function createMockAPI() {
  const handlers = new Map<string, HandlerFn>();
  const entries: Array<{ type: string; data: unknown }> = [];

  const api: ExtensionAPI = {
    on(event: string, handler: HandlerFn) {
      handlers.set(event, handler);
    },
    registerCommand() {},
    registerMarkdownTransformer() {},
    appendEntry(type: string, data?: unknown) {
      entries.push({ type, data });
    },
  };

  return { api, handlers, entries };
}

function createMockCtx(): ExtensionContext {
  return {
    ui: {
      notify: vi.fn(),
      setStatus: vi.fn(),
      confirm: vi.fn(),
    },
    cwd: "/tmp/test",
    isProjectTrusted: () => true,
    abort: vi.fn(),
  };
}

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

function textOf(message: ContextMessage): string {
  return message.content
    .map((b) => (b.type === "text" ? b.text : ""))
    .join("");
}

describe("§3.3 defense-in-depth hooks", () => {
  let handlers: Map<string, HandlerFn>;
  let entries: Array<{ type: string; data: unknown }>;

  beforeEach(async () => {
    vi.resetModules();
    const mock = createMockAPI();
    handlers = mock.handlers;
    entries = mock.entries;
    const { default: extensionFn } = await import("../src/index.js");
    extensionFn(mock.api);
  });

  const getContext = () =>
    handlers.get("context") as (
      event: ContextEvent,
      ctx: ExtensionContext,
    ) => Promise<ContextEventResult | void>;

  const getMessageEnd = () =>
    handlers.get("message_end") as (
      event: MessageEndEvent,
      ctx: ExtensionContext,
    ) => void;

  const getCompact = () =>
    handlers.get("session_before_compact") as (
      event: SessionBeforeCompactEvent,
      ctx: ExtensionContext,
    ) => Promise<SessionBeforeCompactEventResult | void>;

  const getModelSelect = () =>
    handlers.get("model_select") as (
      event: ModelSelectEvent,
      ctx: ExtensionContext,
    ) => void;

  const getToolResult = () =>
    handlers.get("tool_result") as (
      event: ToolResultEvent,
      ctx: ExtensionContext,
    ) => Promise<ToolResultEventResult | void>;

  test("all four hooks are registered", () => {
    expect(getContext()).toBeDefined();
    expect(getMessageEnd()).toBeDefined();
    expect(getCompact()).toBeDefined();
    expect(getModelSelect()).toBeDefined();
  });

  describe("context", () => {
    test("re-scans and substitutes leaked values", async () => {
      const ctx = createMockCtx();
      const result = await getContext()(
        {
          type: "context",
          messages: [
            { role: "user", content: [{ type: "text", text: "hello" }] },
            {
              role: "user",
              content: [
                { type: "text", text: `key is ${AWS_KEY} ok` },
                {
                  type: "image",
                  source: { type: "base64", data: "AAAA", media_type: "image/png" },
                },
              ],
            },
          ],
        },
        ctx,
      );

      expect(result).toBeDefined();
      const messages = result!.messages;
      expect(messages).toHaveLength(2);
      expect(textOf(messages[0])).toBe("hello");

      const second = textOf(messages[1]);
      expect(second).not.toContain(AWS_KEY);
      expect(second).toMatch(/^key is \[\[AWS_ACCESS_KEY_\d+\]\] ok$/);
      // Non-text blocks pass through untouched.
      expect(messages[1].content[1].type).toBe("image");
      // Roles preserved.
      expect(messages[1].role).toBe("user");
    });

    test("passes clean messages through unchanged", async () => {
      const ctx = createMockCtx();
      const clean: ContextMessage[] = [
        { role: "system", content: [{ type: "text", text: "be helpful" }] },
        { role: "user", content: [{ type: "text", text: "list files" }] },
        {
          role: "assistant",
          content: [{ type: "text", text: "sure, running ls" }],
        },
      ];
      const result = await getContext()({ type: "context", messages: clean }, ctx);

      expect(result).toBeDefined();
      expect(result!.messages).toEqual(clean);
      expect(entries).toHaveLength(0);
      expect(ctx.ui.notify).not.toHaveBeenCalled();
    });

    test("logs sanitize_context_rescan_fired when it finds something", async () => {
      const ctx = createMockCtx();
      await getContext()(
        {
          type: "context",
          messages: [
            {
              role: "user",
              content: [
                { type: "text", text: `${AWS_KEY} and AKIAJ7ZQ9X2M5N8P1R4T` },
              ],
            },
          ],
        },
        ctx,
      );

      const fired = entries.filter(
        (e) => e.type === "sanitize_context_rescan_fired",
      );
      expect(fired).toHaveLength(1);
      expect(fired[0].data).toEqual({ count: 2 });
      expect(ctx.ui.notify).toHaveBeenCalledWith(
        expect.stringContaining("re-scan caught 2 span(s)"),
        "warning",
      );
    });
  });

  describe("message_end", () => {
    test("detects raw vault values echoed in assistant text", async () => {
      // Seed the vault via a tool_result scrub.
      await getToolResult()(
        {
          type: "tool_result",
          toolCallId: "tc_1",
          toolName: "bash",
          input: { command: "cat creds" },
          content: [{ type: "text", text: `id=${AWS_KEY}` }],
          isError: false,
        },
        createMockCtx(),
      );
      entries.length = 0;

      const ctx = createMockCtx();
      getMessageEnd()(
        {
          type: "message_end",
          role: "assistant",
          text: `Your access key is ${AWS_KEY}, rotate it.`,
        },
        ctx,
      );

      const leaks = entries.filter(
        (e) => e.type === "sanitize_assistant_leak_detected",
      );
      expect(leaks).toHaveLength(1);
      expect(leaks[0].data).toEqual({ count: 1 });
      expect(ctx.ui.notify).toHaveBeenCalledWith(
        expect.stringContaining("1 raw vault value(s)"),
        "warning",
      );
    });

    test("stays silent when assistant text has no raw values", async () => {
      await getToolResult()(
        {
          type: "tool_result",
          toolCallId: "tc_1",
          toolName: "bash",
          input: { command: "cat creds" },
          content: [{ type: "text", text: `id=${AWS_KEY}` }],
          isError: false,
        },
        createMockCtx(),
      );
      entries.length = 0;

      const ctx = createMockCtx();
      getMessageEnd()(
        {
          type: "message_end",
          role: "assistant",
          text: "Your access key is [[AWS_ACCESS_KEY_1]], rotate it.",
        },
        ctx,
      );

      expect(entries).toHaveLength(0);
      expect(ctx.ui.notify).not.toHaveBeenCalled();
    });

    test("ignores short raw values (< 8 chars)", async () => {
      // Seed the vault with a 4-char value via the PIN detector pattern.
      const seed = await getToolResult()(
        {
          type: "tool_result",
          toolCallId: "tc_1",
          toolName: "bash",
          input: { command: "cat creds" },
          content: [{ type: "text", text: "pin=1234" }],
          isError: false,
        },
        createMockCtx(),
      );
      // Sanity: the short value really is in the vault.
      expect(textOf({ role: "user", content: seed!.content! })).toMatch(
        /^pin=\[\[PIN_\d+\]\]$/,
      );
      entries.length = 0;

      const ctx = createMockCtx();
      getMessageEnd()(
        { type: "message_end", role: "assistant", text: "your pin is 1234" },
        ctx,
      );

      expect(entries).toHaveLength(0);
      expect(ctx.ui.notify).not.toHaveBeenCalled();
    });

    test("ignores non-assistant messages", () => {
      const ctx = createMockCtx();
      getMessageEnd()(
        {
          type: "message_end",
          role: "user" as unknown as "assistant",
          text: AWS_KEY,
        },
        ctx,
      );
      expect(entries).toHaveLength(0);
    });
  });

  describe("session_before_compact", () => {
    test("re-scans messages and logs sanitize_compact_rescan_fired", async () => {
      const ctx = createMockCtx();
      const result = await getCompact()(
        {
          type: "session_before_compact",
          messages: [
            { role: "user", content: [{ type: "text", text: "clean" }] },
            {
              role: "assistant",
              content: [{ type: "text", text: `leaked ${AWS_KEY}` }],
            },
          ],
        },
        ctx,
      );

      expect(result).toBeDefined();
      expect(textOf(result!.messages[0])).toBe("clean");
      expect(textOf(result!.messages[1])).not.toContain(AWS_KEY);
      expect(textOf(result!.messages[1])).toMatch(
        /^leaked \[\[AWS_ACCESS_KEY_\d+\]\]$/,
      );

      const fired = entries.filter(
        (e) => e.type === "sanitize_compact_rescan_fired",
      );
      expect(fired).toHaveLength(1);
      expect(fired[0].data).toEqual({ count: 1 });
      expect(
        entries.some((e) => e.type === "sanitize_context_rescan_fired"),
      ).toBe(false);
    });

    test("passes clean messages through without logging", async () => {
      const ctx = createMockCtx();
      const clean: ContextMessage[] = [
        { role: "user", content: [{ type: "text", text: "nothing here" }] },
      ];
      const result = await getCompact()(
        { type: "session_before_compact", messages: clean },
        ctx,
      );
      expect(result!.messages).toEqual(clean);
      expect(entries).toHaveLength(0);
    });
  });

  describe("model_select", () => {
    test.each(["ollama", "llama.cpp", "llamacpp", "local", "lmstudio", "Ollama"])(
      "warns on local provider %s",
      (provider) => {
        const ctx = createMockCtx();
        getModelSelect()(
          { type: "model_select", model: "llama3", provider },
          ctx,
        );
        expect(ctx.ui.notify).toHaveBeenCalledTimes(1);
        expect(ctx.ui.notify).toHaveBeenCalledWith(
          "sanitize: local model selected — scrubbing still active (overhead may be unnecessary)",
          "info",
        );
      },
    );

    test.each(["anthropic", "openai", "google", "bedrock", "openrouter"])(
      "stays silent on cloud provider %s",
      (provider) => {
        const ctx = createMockCtx();
        getModelSelect()(
          { type: "model_select", model: "some-model", provider },
          ctx,
        );
        expect(ctx.ui.notify).not.toHaveBeenCalled();
      },
    );
  });

  describe("fail-closed", () => {
    test("context withholds content when sanitize is unavailable", async () => {
      vi.resetModules();
      class FailClosedError extends Error {
        constructor() {
          super("sanitize is unavailable");
          this.name = "SanitizeUnavailableError";
        }
      }
      vi.doMock("../src/client.js", () => ({
        SanitizeClient: class {
          async detect() {
            throw new FailClosedError();
          }
          async health() {
            return false;
          }
        },
        SanitizeUnavailableError: FailClosedError,
        PolicyVerificationError: class extends Error {},
      }));

      const mock = createMockAPI();
      const { default: extensionFn } = await import("../src/index.js");
      extensionFn(mock.api);

      const contextHandler = mock.handlers.get("context") as (
        event: ContextEvent,
        ctx: ExtensionContext,
      ) => Promise<ContextEventResult | void>;
      const ctx = createMockCtx();
      const result = await contextHandler(
        {
          type: "context",
          messages: [
            { role: "user", content: [{ type: "text", text: `x ${AWS_KEY}` }] },
          ],
        },
        ctx,
      );

      expect(result).toBeDefined();
      expect(result!.messages).toHaveLength(1);
      expect(result!.messages[0].role).toBe("user");
      expect(textOf(result!.messages[0])).toBe(
        "[[SCRUBBER_UNAVAILABLE: content withheld]]",
      );
      expect(ctx.ui.notify).toHaveBeenCalledWith(
        expect.stringContaining("fail-closed"),
        "error",
      );
    });
  });
});
