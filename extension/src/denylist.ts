import { homedir } from "node:os";
import { resolve, normalize } from "node:path";

const DEFAULT_DENY_PATTERNS = [
  "~/.ssh/**",
  "**/.env",
  "**/.env.*",
  "**/.env*",
  "**/*.pem",
  "**/*.key",
  "**/*.p12",
  "~/.aws/credentials",
  "~/.kube/config",
  "~/.netrc",
  "**/*.ovpn",
  "**/*.tfstate",
];

function expandTilde(pattern: string, home: string): string {
  if (pattern.startsWith("~/")) {
    return home + pattern.slice(1);
  }
  return pattern;
}

function patternToRegex(pattern: string): RegExp {
  let regex = "";
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === "*" && pattern[i + 1] === "*") {
      if (pattern[i + 2] === "/") {
        regex += "(?:.*/)?";
        i += 3;
      } else {
        regex += ".*";
        i += 2;
      }
    } else if (ch === "*") {
      regex += "[^/]*";
      i++;
    } else if (ch === "?") {
      regex += "[^/]";
      i++;
    } else if (".+^${}()|[]\\".includes(ch)) {
      regex += "\\" + ch;
      i++;
    } else {
      regex += ch;
      i++;
    }
  }
  return new RegExp("(?:^|/)" + regex + "$");
}

export function isDeniedPath(
  path: string,
  home?: string,
  extraPatterns?: string[],
): boolean {
  const h = home ?? homedir();
  const allPatterns = [...DEFAULT_DENY_PATTERNS, ...(extraPatterns ?? [])];
  const normalizedPath = normalize(resolve(path));

  for (const raw of allPatterns) {
    const expanded = expandTilde(raw, h);

    if (!expanded.includes("*") && !expanded.includes("?")) {
      const normalizedPattern = normalize(resolve(expanded));
      if (normalizedPath === normalizedPattern) return true;
      if (normalizedPath.startsWith(normalizedPattern + "/")) return true;
      continue;
    }

    const regex = patternToRegex(expanded);
    if (regex.test(normalizedPath)) return true;
  }

  return false;
}
