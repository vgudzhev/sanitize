export class Vault {
  private forward = new Map<string, string>();
  private reverse = new Map<string, string>();
  private counters = new Map<string, number>();
  private redactedCount = 0;

  getPlaceholder(value: string, type: string): string {
    const existing = this.reverse.get(value);
    if (existing) return existing;

    const count = (this.counters.get(type) ?? 0) + 1;
    this.counters.set(type, count);
    const placeholder = `[[${type}_${count}]]`;
    this.forward.set(placeholder, value);
    this.reverse.set(value, placeholder);
    this.redactedCount++;
    return placeholder;
  }

  rehydrate(text: string): string {
    return text.replace(/\[\[[A-Z_]+_\d+\]\]/g, (match) => {
      return this.forward.get(match) ?? match;
    });
  }

  getRedactedCount(): number {
    return this.redactedCount;
  }

  listPlaceholders(): Array<{ placeholder: string; type: string }> {
    return Array.from(this.forward.keys()).map((placeholder) => {
      const inner = placeholder.slice(2, -2);
      const lastUnderscore = inner.lastIndexOf("_");
      const type = inner.slice(0, lastUnderscore);
      return { placeholder, type };
    });
  }

  clear(): void {
    this.forward.clear();
    this.reverse.clear();
    this.counters.clear();
    this.redactedCount = 0;
  }
}
