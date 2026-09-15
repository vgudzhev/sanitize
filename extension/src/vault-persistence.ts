import { createCipheriv, createDecipheriv, randomBytes, pbkdf2Sync } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const PBKDF2_ITERATIONS = 100_000;

interface VaultData {
  forward: Record<string, string>;
  counters: Record<string, number>;
  redactedCount: number;
  formatPreserving: boolean;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

export function encryptVault(data: VaultData, passphrase: string): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(passphrase, salt);
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const json = JSON.stringify(data);
  const encrypted = Buffer.concat([cipher.update(json, "utf-8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Layout: salt(16) + iv(12) + authTag(16) + ciphertext
  return Buffer.concat([salt, iv, authTag, encrypted]);
}

export function decryptVault(blob: Buffer, passphrase: string): VaultData {
  const salt = blob.subarray(0, SALT_LENGTH);
  const iv = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const authTag = blob.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + 16);
  const encrypted = blob.subarray(SALT_LENGTH + IV_LENGTH + 16);

  const key = deriveKey(passphrase, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(decrypted.toString("utf-8"));
}

export function saveVault(
  filePath: string,
  data: VaultData,
  passphrase: string,
): void {
  mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
  const blob = encryptVault(data, passphrase);
  writeFileSync(filePath, blob, { mode: 0o600 });
}

export function loadVault(
  filePath: string,
  passphrase: string,
): VaultData | null {
  try {
    const blob = readFileSync(filePath);
    return decryptVault(blob, passphrase);
  } catch {
    return null;
  }
}

export function deleteVaultFile(filePath: string): void {
  try {
    unlinkSync(filePath);
  } catch {
    // Already gone
  }
}

export type { VaultData };
