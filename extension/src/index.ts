import { homedir } from "node:os";
import type {
  ExtensionAPI,
  ToolCallEvent,
  ContentBlock,
} from "./types.js";
import { Vault } from "./vault.js";
import { substitute } from "./substitute.js";
import { SanitizeClient, SanitizeUnavailableError } from "./client.js";
import { verifyEgress } from "./egress.js";
import { isDeniedPath } from "./denylist.js";
import { loadConfig } from "./config.js";
import { registerSanitizeCommand } from "./ui.js";

function extractPathFromToolCall(event: ToolCallEvent): string | null {
  const input = event.input;
  if (event.toolName === "read" || event.toolName === "edit" || event.toolName === "write") {
    const fp = input.file_path;
    if (typeof fp === "string") return fp;
  }
  if (event.toolName === "bash") {
    const command = input.command;
    if (typeof command === "string") {
      const catMatch = command.match(
        /\b(?:cat|head|tail|less|more|bat)\s+['"]?([^\s'";&|]+)/,
      );
      if (catMatch) return catMatch[1];
    }
  }
  return null;
}

function rehydrateToolInput(
  input: Record<string, unknown>,
  vault: Vault,
): void {
  for (const key of Object.keys(input)) {
    const value = input[key];
    if (typeof value === "string") {
      input[key] = vault.rehydrate(value);
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        if (typeof value[i] === "string") {
          value[i] = vault.rehydrate(value[i]);
        }
      }
    } else if (value !== null && typeof value === "object") {
      rehydrateToolInput(value as Record<string, unknown>, vault);
    }
  }
}

const extension = (api: ExtensionAPI) => {
  const config = loadConfig(process.cwd(), false);
  const vault = new Vault();
  const client = new SanitizeClient(config.sanitize.url, config.sanitize.timeout_ms);
  const home = homedir();

  api.on("session_start", async (_event, ctx) => {
    const healthy = await client.health();
    if (!healthy) {
      ctx.ui.notify(
        "sanitize is not reachable — all requests will be blocked (fail-closed)",
        "warning",
      );
    }
    ctx.ui.setStatus(
      "sanitize",
      `sanitize: on · ${vault.getRedactedCount()} redacted`,
    );
  });

  api.on("input", async (event, ctx) => {
    try {
      const result = await client.detect({
        text: event.text,
        hints: { source: "input" },
      });
      if (result.spans.length === 0) return { action: "continue" as const };
      const scrubbed = substitute(event.text, result.spans, vault);
      ctx.ui.setStatus(
        "sanitize",
        `sanitize: on · ${vault.getRedactedCount()} redacted`,
      );
      return { action: "transform" as const, text: scrubbed };
    } catch (e) {
      if (e instanceof SanitizeUnavailableError) {
        ctx.ui.notify("sanitize unavailable — input withheld (fail-closed)", "error");
        return {
          action: "transform" as const,
          text: "[[SCRUBBER_UNAVAILABLE: content withheld]]",
        };
      }
      throw e;
    }
  });

  api.on("tool_call", (event, ctx) => {
    const path = extractPathFromToolCall(event);
    if (path && isDeniedPath(path, home, config.deny_paths)) {
      return {
        block: true,
        reason: `Blocked: ${path} is on the sensitive-file deny list`,
      };
    }
    rehydrateToolInput(event.input, vault);
  });

  api.on("tool_result", async (event, ctx) => {
    try {
      const newContent: ContentBlock[] = await Promise.all(
        event.content.map(async (block) => {
          if (block.type !== "text") return block;
          const result = await client.detect({
            text: block.text,
            hints: { source: "tool_result", tool: event.toolName },
          });
          if (result.spans.length === 0) return block;
          return {
            type: "text" as const,
            text: substitute(block.text, result.spans, vault),
          };
        }),
      );
      ctx.ui.setStatus(
        "sanitize",
        `sanitize: on · ${vault.getRedactedCount()} redacted`,
      );
      return { content: newContent };
    } catch (e) {
      if (e instanceof SanitizeUnavailableError) {
        ctx.ui.notify(
          "sanitize unavailable — tool result withheld (fail-closed)",
          "error",
        );
        return {
          content: [
            {
              type: "text" as const,
              text: "[[SCRUBBER_UNAVAILABLE: content withheld]]",
            },
          ],
        };
      }
      throw e;
    }
  });

  api.on("before_provider_request", (event, ctx) => {
    const payloadStr = JSON.stringify(event.payload);
    const result = verifyEgress(payloadStr);
    if (!result.safe) {
      ctx.ui.notify(
        `Egress blocked: ${result.violations.join(", ")}`,
        "error",
      );
      ctx.abort();
    }
  });

  api.registerMarkdownTransformer((markdown) => {
    return vault.rehydrate(markdown);
  });

  registerSanitizeCommand(api, vault, client);

  api.on("session_shutdown", () => {
    vault.clear();
  });
};

export default extension;
