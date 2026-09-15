import { formatPlaceholder } from "./format.js";

export class Vault {
  private forward = new Map<string, string>();
  private reverse = new Map<string, string>();
  private counters = new Map<string, number>();
  private redactedCount = 0;
  private formatPreserving: boolean;

  constructor(formatPreserving = false) {
    this.formatPreserving = formatPreserving;
  }

  getPlaceholder(value: string, type: string): string {
    const existing = this.reverse.get(value);
    if (existing) return existing;

    const count = (this.counters.get(type) ?? 0) + 1;
    this.counters.set(type, count);
    const placeholder = this.formatPreserving
      ? formatPlaceholder(type, count)
      : `[[${type}_${count}]]`;
    this.forward.set(placeholder, value);
    this.reverse.set(value, placeholder);
    this.redactedCount++;
    return placeholder;
  }

  rehydrate(text: string): string {
    if (this.formatPreserving) {
      let result = text;
      for (const [placeholder, value] of this.forward) {
        let idx = result.indexOf(placeholder);
        while (idx !== -1) {
          result =
            result.slice(0, idx) + value + result.slice(idx + placeholder.length);
          idx = result.indexOf(placeholder, idx + value.length);
        }
      }
      return result;
    }
    return text.replace(/\[\[[A-Z_]+_\d+\]\]/g, (match) => {
      return this.forward.get(match) ?? match;
    });
  }

  getRedactedCount(): number {
    return this.redactedCount;
  }

  getRawValues(): string[] {
    return Array.from(this.reverse.keys());
  }

  revealValue(placeholder: string): string {
    return this.forward.get(placeholder) ?? "(unknown)";
  }

  listPlaceholders(): Array<{ placeholder: string; type: string }> {
    return Array.from(this.forward.keys()).map((placeholder) => {
      const bracketMatch = placeholder.match(/^\[\[([A-Z_]+)_\d+\]\]$/);
      if (bracketMatch) {
        return { placeholder, type: bracketMatch[1] };
      }
      for (const [type] of this.counters) {
        const count = this._findCounterForPlaceholder(placeholder, type);
        if (count !== null) return { placeholder, type };
      }
      return { placeholder, type: "UNKNOWN" };
    });
  }

  private _findCounterForPlaceholder(
    placeholder: string,
    type: string,
  ): number | null {
    const maxCount = this.counters.get(type) ?? 0;
    for (let i = 1; i <= maxCount; i++) {
      if (formatPlaceholder(type, i) === placeholder) return i;
    }
    return null;
  }

  isFormatPreserving(): boolean {
    return this.formatPreserving;
  }

  serialize(): {
    forward: Record<string, string>;
    counters: Record<string, number>;
    redactedCount: number;
    formatPreserving: boolean;
  } {
    return {
      forward: Object.fromEntries(this.forward),
      counters: Object.fromEntries(this.counters),
      redactedCount: this.redactedCount,
      formatPreserving: this.formatPreserving,
    };
  }

  static restore(data: {
    forward: Record<string, string>;
    counters: Record<string, number>;
    redactedCount: number;
    formatPreserving: boolean;
  }): Vault {
    const vault = new Vault(data.formatPreserving);
    for (const [placeholder, value] of Object.entries(data.forward)) {
      vault.forward.set(placeholder, value);
      vault.reverse.set(value, placeholder);
    }
    for (const [type, count] of Object.entries(data.counters)) {
      vault.counters.set(type, count);
    }
    vault.redactedCount = data.redactedCount;
    return vault;
  }

  restoreFrom(data: {
    forward: Record<string, string>;
    counters: Record<string, number>;
    redactedCount: number;
    formatPreserving: boolean;
  }): void {
    this.forward.clear();
    this.reverse.clear();
    this.counters.clear();
    this.formatPreserving = data.formatPreserving;
    for (const [placeholder, value] of Object.entries(data.forward)) {
      this.forward.set(placeholder, value);
      this.reverse.set(value, placeholder);
    }
    for (const [type, count] of Object.entries(data.counters)) {
      this.counters.set(type, count);
    }
    this.redactedCount = data.redactedCount;
  }

  clear(): void {
    this.forward.clear();
    this.reverse.clear();
    this.counters.clear();
    this.redactedCount = 0;
  }
}
