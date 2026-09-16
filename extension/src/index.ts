import { homedir } from "node:os";
import { join } from "node:path";
import type {
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
  ContentBlock,
  ContextMessage,
} from "./types.js";
import { Vault } from "./vault.js";
import { substitute } from "./substitute.js";
import { SanitizeClient, SanitizeUnavailableError, PolicyVerificationError } from "./client.js";
import { verifyEgress } from "./egress.js";
import { isDeniedPath } from "./denylist.js";
import { loadConfig, loadProjectArrays, applyProjectArrays } from "./config.js";
import { registerSanitizeCommand } from "./ui.js";
import { saveVault, loadVault, deleteVaultFile } from "./vault-persistence.js";
import { AuditEmitter } from "./audit.js";

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

// Providers that run inference on the user's own machine. Scrubbing is still
// on for these (the session may later switch to a cloud model), but it's
// worth telling the user the overhead is optional.
const LOCAL_PROVIDERS = new Set([
  "ollama",
  "llama.cpp",
  "llamacpp",
  "local",
  "lmstudio",
]);

export function isLocalProvider(provider: string): boolean {
  return LOCAL_PROVIDERS.has(provider.trim().toLowerCase());
}

const extension = (api: ExtensionAPI) => {
  const config = loadConfig(process.cwd());
  let vault = new Vault(config.placeholders?.format_preserving ?? false);
  const client = new SanitizeClient(
    config.sanitize.url,
    config.sanitize.timeout_ms,
    config.org.token,
  );
  const home = homedir();
  const vaultPath = join(home, ".sanitize", "vault.enc");
  const vaultPassphrase = process.env.SANITIZE_VAULT_KEY ?? null;

  const audit: AuditEmitter | null =
    config.org.audit_url ? new AuditEmitter(config.org.audit_url, config.org.token) : null;

  let policyVersion = "local";
  let policyVerificationFailed = false;

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

    if (config.org.policy_url) {
      try {
        const policyResp = await client.fetchPolicy(config.org.public_key);
        policyVersion = policyResp.policy_version;

        const central = policyResp.policy;
        if (Array.isArray(central.deny_paths)) {
          const existing = new Set(config.deny_paths);
          for (const p of central.deny_paths as string[]) {
            if (!existing.has(p)) config.deny_paths.push(p);
          }
        }
        if (Array.isArray(central.allow)) {
          const centralAllow = new Set(central.allow as string[]);
          config.allow = config.allow.filter((a) => centralAllow.has(a));
        }

        ctx.ui.notify(
          `sanitize: org policy loaded (v${policyVersion})`,
          "info",
        );
      } catch (e) {
        if (e instanceof PolicyVerificationError) {
          policyVerificationFailed = true;
          ctx.ui.notify(
            `sanitize: BLOCKED — org policy signature invalid`,
            "error",
          );
        } else {
          const msg = e instanceof Error ? e.message : "unknown error";
          ctx.ui.notify(
            `sanitize: failed to fetch org policy — ${msg}`,
            "error",
          );
        }
      }
    }

    if (ctx.isProjectTrusted()) {
      const projectArrays = loadProjectArrays(ctx.cwd);
      if (projectArrays) {
        applyProjectArrays(config, projectArrays);
      }
    }

    ctx.ui.setStatus(
      "sanitize",
      `sanitize: on · ${vault.getRedactedCount()} redacted`,
    );
  });

  api.on("input", async (event, ctx) => {
    if (policyVerificationFailed) {
      return {
        action: "transform" as const,
        text: "[[ORG_POLICY_INVALID: content withheld]]",
      };
    }
    try {
      const result = await client.detect({
        text: event.text,
        hints: { source: "input" },
      });
      if (result.spans.length === 0) return { action: "continue" as const };
      const scrubbed = substitute(event.text, result.spans, vault);
      if (audit) audit.emit(result.spans, "input", result.policy_version);
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
    if (policyVerificationFailed) {
      return {
        content: [
          {
            type: "text" as const,
            text: "[[ORG_POLICY_INVALID: content withheld]]",
          },
        ],
      };
    }
    try {
      const newContent: ContentBlock[] = await Promise.all(
        event.content.map(async (block) => {
          if (block.type !== "text") return block;
          const result = await client.detect({
            text: block.text,
            hints: { source: "tool_result", tool: event.toolName },
          });
          if (result.spans.length === 0) return block;
          if (audit) audit.emit(result.spans, "tool_result", result.policy_version);
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
      return;
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

  // Shared by `context` and `session_before_compact`: re-scan every text block
  // in the message list and substitute anything found. Ingress scrubbing
  // (input / tool_result) should have caught everything already, so a hit
  // here indicates a bug elsewhere — log it so it's visible.
  const withheldMessages = (
    messages: ContextMessage[],
    text: string,
  ): ContextMessage[] =>
    messages.map((m) => ({
      role: m.role,
      content: [{ type: "text" as const, text }],
    }));

  const rescanMessages = async (
    messages: ContextMessage[],
    source: "context" | "session_before_compact",
    entryType: string,
    ctx: ExtensionContext,
  ): Promise<{ messages: ContextMessage[] }> => {
    if (policyVerificationFailed) {
      return {
        messages: withheldMessages(
          messages,
          "[[ORG_POLICY_INVALID: content withheld]]",
        ),
      };
    }
    try {
      let found = 0;
      const rescanned: ContextMessage[] = await Promise.all(
        messages.map(async (message) => {
          const content: ContentBlock[] = await Promise.all(
            message.content.map(async (block) => {
              if (block.type !== "text") return block;
              const result = await client.detect({
                text: block.text,
                hints: { source },
              });
              if (result.spans.length === 0) return block;
              found += result.spans.length;
              if (audit) audit.emit(result.spans, source, result.policy_version);
              return {
                type: "text" as const,
                text: substitute(block.text, result.spans, vault),
              };
            }),
          );
          return { role: message.role, content };
        }),
      );
      if (found > 0) {
        api.appendEntry(entryType, { count: found });
        ctx.ui.notify(
          `sanitize: ${source} re-scan caught ${found} span(s) that ingress missed (this should never fire — please report)`,
          "warning",
        );
        ctx.ui.setStatus(
          "sanitize",
          `sanitize: on · ${vault.getRedactedCount()} redacted`,
        );
      }
      return { messages: rescanned };
    } catch (e) {
      if (e instanceof SanitizeUnavailableError) {
        ctx.ui.notify(
          `sanitize unavailable — ${source} withheld (fail-closed)`,
          "error",
        );
        return {
          messages: withheldMessages(
            messages,
            "[[SCRUBBER_UNAVAILABLE: content withheld]]",
          ),
        };
      }
      throw e;
    }
  };

  api.on("context", (event, ctx) =>
    rescanMessages(
      event.messages,
      "context",
      "sanitize_context_rescan_fired",
      ctx,
    ),
  );

  api.on("session_before_compact", (event, ctx) =>
    rescanMessages(
      event.messages,
      "session_before_compact",
      "sanitize_compact_rescan_fired",
      ctx,
    ),
  );

  // Cheap sanity metric: did the model echo back a raw secret that somehow
  // survived in its context? Log only — the assistant text is already
  // displayed locally, and the placeholder→value direction is what the
  // markdown transformer does on purpose.
  api.on("message_end", (event, ctx) => {
    if (event.role !== "assistant") return;
    let leaked = 0;
    for (const raw of vault.getRawValues()) {
      if (raw.length >= 8 && event.text.includes(raw)) leaked++;
    }
    if (leaked > 0) {
      api.appendEntry("sanitize_assistant_leak_detected", { count: leaked });
      ctx.ui.notify(
        `sanitize: assistant output contains ${leaked} raw vault value(s) — a secret reached the model unscrubbed (please report)`,
        "warning",
      );
    }
  });

  api.on("model_select", (event, ctx) => {
    if (isLocalProvider(event.provider)) {
      ctx.ui.notify(
        "sanitize: local model selected — scrubbing still active (overhead may be unnecessary)",
        "info",
      );
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
