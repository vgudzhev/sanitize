import { homedir } from "node:os";
import { join } from "node:path";
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
import { saveVault, loadVault, deleteVaultFile } from "./vault-persistence.js";

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
  let vault = new Vault(config.placeholders?.format_preserving ?? false);
  const client = new SanitizeClient(config.sanitize.url, config.sanitize.timeout_ms);
  const home = homedir();
  const vaultPath = join(home, ".sanitize", "vault.enc");
  const vaultPassphrase = process.env.SANITIZE_VAULT_KEY ?? null;

  const restoreVault = (): number => {
    if (!vaultPassphrase) return 0;
    const restored = loadVault(vaultPath, vaultPassphrase);
    if (restored) {
      vault.restoreFrom(restored);
      return vault.getRedactedCount();
    }
    return 0;
  };

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

    const rawValues = vault.getRawValues();
    if (rawValues.length > 0) {
      let leakedCount = 0;
      for (const raw of rawValues) {
        if (raw.length >= 8 && payloadStr.includes(raw)) {
          leakedCount++;
        }
      }
      if (leakedCount > 0) {
        api.appendEntry("sanitize_context_rescan_fired", {
          count: leakedCount,
        });
        ctx.ui.notify(
          `Context re-scan: ${leakedCount} raw value(s) found in outgoing payload (this should never fire — please report)`,
          "error",
        );
        ctx.abort();
      }
    }
  });

  api.registerMarkdownTransformer((markdown) => {
    return vault.rehydrate(markdown);
  });

  registerSanitizeCommand(api, vault, client, restoreVault);

  api.on("session_shutdown", () => {
    if (vaultPassphrase && vault.getRedactedCount() > 0) {
      try {
        saveVault(vaultPath, vault.serialize(), vaultPassphrase);
      } catch {
        // Best-effort — don't crash shutdown
      }
    } else if (vaultPassphrase) {
      deleteVaultFile(vaultPath);
    }
    vault.clear();
  });
};

export default extension;
