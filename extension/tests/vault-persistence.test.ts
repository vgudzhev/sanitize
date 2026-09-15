import { describe, it, expect, afterEach } from "vitest";
import { join } from "node:path";
import { existsSync, unlinkSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  encryptVault,
  decryptVault,
  saveVault,
  loadVault,
  deleteVaultFile,
} from "../src/vault-persistence.js";
import { Vault } from "../src/vault.js";
import type { VaultData } from "../src/vault-persistence.js";

const TEST_DIR = join(tmpdir(), "sanitize-vault-test");
const TEST_FILE = join(TEST_DIR, "vault.enc");
const PASSPHRASE = "test-passphrase-123";

afterEach(() => {
  try {
    unlinkSync(TEST_FILE);
  } catch {
    // ignore
  }
});

describe("encrypt/decrypt roundtrip", () => {
  const data: VaultData = {
    forward: { "[[EMAIL_1]]": "a@b.com", "[[IP_1]]": "10.1.2.3" },
    counters: { EMAIL: 1, IP: 1 },
    redactedCount: 2,
    formatPreserving: false,
  };

  it("decrypts to the same data that was encrypted", () => {
    const blob = encryptVault(data, PASSPHRASE);
    const restored = decryptVault(blob, PASSPHRASE);
    expect(restored).toEqual(data);
  });

  it("fails with wrong passphrase", () => {
    const blob = encryptVault(data, PASSPHRASE);
    expect(() => decryptVault(blob, "wrong-key")).toThrow();
  });

  it("produces different ciphertexts for same data (random salt/IV)", () => {
    const a = encryptVault(data, PASSPHRASE);
    const b = encryptVault(data, PASSPHRASE);
    expect(a.equals(b)).toBe(false);
  });
});

describe("saveVault / loadVault", () => {
  it("saves and loads vault data", () => {
    const data: VaultData = {
      forward: { "[[TOKEN_1]]": "ghp_abc123" },
      counters: { TOKEN: 1 },
      redactedCount: 1,
      formatPreserving: false,
    };
    saveVault(TEST_FILE, data, PASSPHRASE);
    expect(existsSync(TEST_FILE)).toBe(true);

    const restored = loadVault(TEST_FILE, PASSPHRASE);
    expect(restored).toEqual(data);
  });

  it("returns null for missing file", () => {
    expect(loadVault("/nonexistent/path.enc", PASSPHRASE)).toBeNull();
  });

  it("returns null for wrong passphrase", () => {
    const data: VaultData = {
      forward: {},
      counters: {},
      redactedCount: 0,
      formatPreserving: false,
    };
    saveVault(TEST_FILE, data, PASSPHRASE);
    expect(loadVault(TEST_FILE, "wrong")).toBeNull();
  });
});

describe("deleteVaultFile", () => {
  it("removes the file", () => {
    mkdirSync(TEST_DIR, { recursive: true });
    const data: VaultData = {
      forward: {},
      counters: {},
      redactedCount: 0,
      formatPreserving: false,
    };
    saveVault(TEST_FILE, data, PASSPHRASE);
    expect(existsSync(TEST_FILE)).toBe(true);
    deleteVaultFile(TEST_FILE);
    expect(existsSync(TEST_FILE)).toBe(false);
  });

  it("does not throw for missing file", () => {
    expect(() => deleteVaultFile("/nonexistent/file.enc")).not.toThrow();
  });
});

describe("Vault serialize/restore", () => {
  it("roundtrips vault state through serialize/restore", () => {
    const vault = new Vault(false);
    vault.getPlaceholder("a@b.com", "EMAIL");
    vault.getPlaceholder("10.1.2.3", "IP_ADDRESS");
    vault.getPlaceholder("x@y.com", "EMAIL");

    const data = vault.serialize();
    const restored = Vault.restore(data);

    expect(restored.getRedactedCount()).toBe(3);
    expect(restored.revealValue("[[EMAIL_1]]")).toBe("a@b.com");
    expect(restored.revealValue("[[EMAIL_2]]")).toBe("x@y.com");
    expect(restored.revealValue("[[IP_ADDRESS_1]]")).toBe("10.1.2.3");
    expect(restored.rehydrate("Send to [[EMAIL_1]] at [[IP_ADDRESS_1]]")).toBe(
      "Send to a@b.com at 10.1.2.3",
    );
  });

  it("restored vault assigns new placeholders continuing from saved counters", () => {
    const vault = new Vault(false);
    vault.getPlaceholder("a@b.com", "EMAIL");

    const restored = Vault.restore(vault.serialize());
    const p = restored.getPlaceholder("z@w.com", "EMAIL");
    expect(p).toBe("[[EMAIL_2]]");
  });

  it("roundtrips format-preserving vault", () => {
    const vault = new Vault(true);
    vault.getPlaceholder("a@b.com", "EMAIL");

    const data = vault.serialize();
    expect(data.formatPreserving).toBe(true);

    const restored = Vault.restore(data);
    expect(restored.isFormatPreserving()).toBe(true);
    expect(restored.revealValue("user1@redacted.example")).toBe("a@b.com");
  });
});
