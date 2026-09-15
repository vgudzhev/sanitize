import type { ExtensionAPI } from "./types.js";
import type { Vault } from "./vault.js";
import type { SanitizeClient } from "./client.js";

export function registerSanitizeCommand(
  api: ExtensionAPI,
  vault: Vault,
  client: SanitizeClient,
  restoreVault?: () => number,
): void {
  api.registerCommand("sanitize", {
    description: "Manage sanitize: status, show, test <text>, reveal, resume",
    handler: async (args, ctx) => {
      const [subcommand, ...rest] = args.trim().split(/\s+/);

      switch (subcommand) {
        case "status":
        case "": {
          const healthy = await client.health();
          const lines = [
            `sanitize: ${healthy ? "reachable" : "UNREACHABLE"}`,
            `url: ${(client as any).baseUrl ?? "http://127.0.0.1:7411"}`,
            `redacted: ${vault.getRedactedCount()} items`,
            `fail-closed: always`,
          ];
          ctx.ui.notify(lines.join("\n"), healthy ? "info" : "warning");
          break;
        }

        case "show": {
          const placeholders = vault.listPlaceholders();
          if (placeholders.length === 0) {
            ctx.ui.notify("No placeholders in this session.", "info");
          } else {
            const lines = placeholders.map(
              (p) => `${p.placeholder} → [${p.type}]`,
            );
            ctx.ui.notify(lines.join("\n"), "info");
          }
          break;
        }

        case "test": {
          const text = rest.join(" ");
          if (!text) {
            ctx.ui.notify("Usage: /sanitize test <text>", "warning");
            break;
          }
          try {
            const result = await client.detect({ text, hints: { source: "input" } });
            if (result.spans.length === 0) {
              ctx.ui.notify("No sensitive data detected.", "info");
            } else {
              const lines = result.spans.map(
                (s) =>
                  `[${s.start}:${s.end}] ${s.type} (${s.score.toFixed(2)}, ${s.detector})`,
              );
              ctx.ui.notify(
                `Found ${result.spans.length} item(s):\n${lines.join("\n")}`,
                "info",
              );
            }
          } catch {
            ctx.ui.notify("sanitize unreachable — cannot test.", "error");
          }
          break;
        }

        case "reveal": {
          const placeholders = vault.listPlaceholders();
          if (placeholders.length === 0) {
            ctx.ui.notify("No placeholders to reveal.", "info");
            break;
          }
          const confirmed = await ctx.ui.confirm(
            "Reveal sensitive values?",
            `This will display ${placeholders.length} redacted value(s) in plain text. Proceed?`,
          );
          if (!confirmed) {
            ctx.ui.notify("Reveal cancelled.", "info");
            break;
          }
          const target = rest.join(" ").trim();
          const toReveal = target
            ? placeholders.filter(
                (p) => p.placeholder === target || p.type === target,
              )
            : placeholders;
          if (toReveal.length === 0) {
            ctx.ui.notify(`No placeholders matching "${target}".`, "warning");
            break;
          }
          const lines = toReveal.map(
            (p) => `${p.placeholder} → ${vault.revealValue(p.placeholder)}`,
          );
          ctx.ui.notify(lines.join("\n"), "info");
          break;
        }

        case "resume": {
          if (!restoreVault) {
            ctx.ui.notify(
              "Vault persistence not configured. Set SANITIZE_VAULT_KEY env var.",
              "warning",
            );
            break;
          }
          const count = restoreVault();
          if (count > 0) {
            ctx.ui.notify(
              `Vault restored: ${count} redacted item(s) from previous session.`,
              "info",
            );
          } else {
            ctx.ui.notify("No saved vault found.", "info");
          }
          ctx.ui.setStatus(
            "sanitize",
            `sanitize: on · ${vault.getRedactedCount()} redacted`,
          );
          break;
        }

        default:
          ctx.ui.notify(
            "Unknown subcommand. Usage: /sanitize status|show|test|reveal|resume",
            "warning",
          );
      }
    },
  });
}
