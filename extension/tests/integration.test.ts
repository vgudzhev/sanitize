/**
 * §6 acceptance test: end-to-end scrub pipeline.
 *
 * Verifies the named "done when" criterion: a session where `cat config.yaml`
 * containing a DB URL+password, AWS key pair, and private key results in a
 * provider payload containing none of them, and the agent can still run `psql`
 * via rehydrated tool_call args.
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
        {
          regex:
            /-----BEGIN [\w ]+ PRIVATE KEY-----[\s\S]*?-----END [\w ]+ PRIVATE KEY-----/g,
          type: "PRIVATE_KEY",
        },
        {
          regex:
            /(?:postgres|postgresql|mysql|mongodb):\/\/[^:\s]+:[^@\s]+@[^\s]+/gi,
          type: "DB_CONNECTION_URL",
        },
        {
          regex:
            /(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}/gi,
          type: "AWS_SECRET_KEY",
        },
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
  };
});

vi.mock("../src/config.js", () => ({
  loadConfig: () => ({
    sanitize: { url: "http://localhost:7411", timeout_ms: 4000 },
    deny_paths: [],
  }),
}));

vi.mock("node:os", () => ({
  homedir: () => "/home/testuser",
}));

import type {
  ExtensionAPI,
  ExtensionContext,
  InputEvent,
  InputEventResult,
  ToolCallEvent,
  ToolCallEventResult,
  ToolResultEvent,
  ToolResultEventResult,
  BeforeProviderRequestEvent,
} from "../src/types.js";

type HandlerFn = (...args: unknown[]) => unknown;

function createMockAPI() {
  const handlers = new Map<string, HandlerFn>();
  let markdownTransformer: ((md: string) => string) | null = null;

  const api: ExtensionAPI = {
    on(event: string, handler: HandlerFn) {
      handlers.set(event, handler);
    },
    registerCommand() {},
    registerMarkdownTransformer(fn: (md: string) => string) {
      markdownTransformer = fn;
    },
    appendEntry() {},
  };

  return { api, handlers, getMarkdownTransformer: () => markdownTransformer };
}

function createMockCtx(): ExtensionContext & { aborted: boolean } {
  return {
    ui: {
      notify: vi.fn(),
      setStatus: vi.fn(),
      confirm: vi.fn(),
    },
    cwd: "/tmp/test",
    isProjectTrusted: () => true,
    abort: vi.fn(),
    aborted: false,
  };
}

const CONFIG_YAML = `database:
  url: postgres://admin:s3cr3tP4ss@db.internal:5432/myapp

aws:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

ssl:
  private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
    aFDrBz9vFqU4yBwr3U0M3O4PU18A9sVw7PbUexw7t/IZ8FLqOdZby0O1Nj93v0oG
    -----END RSA PRIVATE KEY-----`;

const DB_URL = "postgres://admin:s3cr3tP4ss@db.internal:5432/myapp";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ASSIGNMENT =
  "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const PRIVATE_KEY_BLOCK = `-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
    aFDrBz9vFqU4yBwr3U0M3O4PU18A9sVw7PbUexw7t/IZ8FLqOdZby0O1Nj93v0oG
    -----END RSA PRIVATE KEY-----`;

describe("§6 acceptance: end-to-end scrub pipeline", () => {
  let handlers: Map<string, HandlerFn>;
  let getMarkdownTransformer: () => ((md: string) => string) | null;

  beforeEach(async () => {
    const mock = createMockAPI();
    handlers = mock.handlers;
    getMarkdownTransformer = mock.getMarkdownTransformer;

    const { default: extensionFn } = await import("../src/index.js");
    extensionFn(mock.api);
  });

  test("cat config.yaml → provider payload contains no secrets, psql rehydrates", async () => {
    const ctx = createMockCtx();

    // 1. Simulate tool_result from `cat config.yaml`
    const toolResultHandler = handlers.get("tool_result") as (
      event: ToolResultEvent,
      ctx: ExtensionContext,
    ) => Promise<ToolResultEventResult | void>;
    expect(toolResultHandler).toBeDefined();

    const toolResultEvent: ToolResultEvent = {
      type: "tool_result",
      toolCallId: "tc_1",
      toolName: "bash",
      input: { command: "cat config.yaml" },
      content: [{ type: "text", text: CONFIG_YAML }],
      isError: false,
    };

    const result = await toolResultHandler(toolResultEvent, ctx);
    expect(result).toBeDefined();
    const scrubbedContent = result!.content!;
    expect(scrubbedContent).toHaveLength(1);

    const scrubbedText =
      scrubbedContent[0].type === "text" ? scrubbedContent[0].text : "";

    // Verify none of the secrets appear in the scrubbed output
    expect(scrubbedText).not.toContain(DB_URL);
    expect(scrubbedText).not.toContain(AWS_KEY);
    expect(scrubbedText).not.toContain("s3cr3tP4ss");
    expect(scrubbedText).not.toContain("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    expect(scrubbedText).not.toContain("-----BEGIN RSA PRIVATE KEY-----");

    // Verify placeholders are present
    expect(scrubbedText).toMatch(/\[\[DB_CONNECTION_URL_\d+\]\]/);
    expect(scrubbedText).toMatch(/\[\[AWS_ACCESS_KEY_\d+\]\]/);
    expect(scrubbedText).toMatch(/\[\[PRIVATE_KEY_\d+\]\]/);

    // 2. Verify the scrubbed payload passes egress
    const egressHandler = handlers.get("before_provider_request") as (
      event: BeforeProviderRequestEvent,
      ctx: ExtensionContext,
    ) => void;
    expect(egressHandler).toBeDefined();

    const safeCtx = createMockCtx();
    const safePayload = {
      messages: [
        {
          role: "user",
          content: scrubbedText,
        },
      ],
    };
    egressHandler({ type: "before_provider_request", payload: safePayload }, safeCtx);
    expect(safeCtx.abort).not.toHaveBeenCalled();

    // 3. Verify an unscrubbed payload triggers egress abort
    const unsafeCtx = createMockCtx();
    const unsafePayload = {
      messages: [
        {
          role: "user",
          content: CONFIG_YAML,
        },
      ],
    };
    egressHandler(
      { type: "before_provider_request", payload: unsafePayload },
      unsafeCtx,
    );
    expect(unsafeCtx.abort).toHaveBeenCalled();

    // 4. Simulate tool_call for psql with placeholder — verify rehydration
    const toolCallHandler = handlers.get("tool_call") as (
      event: ToolCallEvent,
      ctx: ExtensionContext,
    ) => ToolCallEventResult | void;
    expect(toolCallHandler).toBeDefined();

    // Extract the DB_CONNECTION_URL placeholder from scrubbed text
    const dbPlaceholder = scrubbedText.match(/\[\[DB_CONNECTION_URL_\d+\]\]/)![0];

    const psqlEvent: ToolCallEvent = {
      type: "tool_call",
      toolCallId: "tc_2",
      toolName: "bash",
      input: {
        command: `psql "${dbPlaceholder}" -c "SELECT 1"`,
      },
    };

    const callCtx = createMockCtx();
    toolCallHandler(psqlEvent, callCtx);

    // After rehydration, the real DB URL should be restored in the input
    expect(psqlEvent.input.command).toContain(DB_URL);
    expect(psqlEvent.input.command).not.toContain("[[DB_CONNECTION_URL");

    // 5. Verify markdown transformer rehydrates for display
    const transformer = getMarkdownTransformer();
    expect(transformer).toBeDefined();
    const displayed = transformer!(scrubbedText);
    expect(displayed).toContain(DB_URL);
    expect(displayed).toContain(AWS_KEY);
  });

  test("fail-closed: sanitize unavailable blocks input", async () => {
    // Re-import with failing client
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
    }));
    vi.doMock("../src/config.js", () => ({
      loadConfig: () => ({
        sanitize: { url: "http://localhost:7411", timeout_ms: 4000 },
        deny_paths: [],
      }),
    }));
    vi.doMock("node:os", () => ({
      homedir: () => "/home/testuser",
    }));

    const { default: extensionFn } = await import("../src/index.js");
    const mock = createMockAPI();
    extensionFn(mock.api);

    const inputHandler = mock.handlers.get("input") as (
      event: InputEvent,
      ctx: ExtensionContext,
    ) => Promise<InputEventResult | void>;

    const ctx = createMockCtx();
    const result = await inputHandler(
      { type: "input", text: "my secret data", source: "interactive" },
      ctx,
    );
    expect(result).toBeDefined();
    expect(result!.action).toBe("transform");
    expect((result as { text: string }).text).toContain(
      "[[SCRUBBER_UNAVAILABLE",
    );
  });
});
