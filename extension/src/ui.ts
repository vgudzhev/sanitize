import type { ExtensionAPI } from "./types.js";
import type { Vault } from "./vault.js";
import type { ScrubdClient } from "./client.js";

export function registerScrubCommand(
  api: ExtensionAPI,
  vault: Vault,
  client: ScrubdClient,
): void {
  api.registerCommand("scrub", {
    description: "Manage pi-scrub: status, show, test <text>",
    handler: async (args, ctx) => {
      const [subcommand, ...rest] = args.trim().split(/\s+/);

      switch (subcommand) {
        case "status":
        case "": {
          const healthy = await client.health();
          const lines = [
            `scrubd: ${healthy ? "reachable" : "UNREACHABLE"}`,
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
            ctx.ui.notify("Usage: /scrub test <text>", "warning");
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
            ctx.ui.notify("scrubd unreachable — cannot test.", "error");
          }
          break;
        }

        default:
          ctx.ui.notify(
            "Unknown subcommand. Usage: /scrub status|show|test <text>",
            "warning",
          );
      }
    },
  });
}
