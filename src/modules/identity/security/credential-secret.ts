import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { emailOutboxEncryptionKey } from "./auth-secrets";

export function generateCredential(): string {
  // Hex is deliberately less compact than base64url but is scanner-friendly,
  // unambiguous when grouped for handover, and still carries 256 bits.
  return randomBytes(32).toString("hex");
}

export function formatVoucher(secret: string): string {
  return secret.match(/.{1,8}/g)?.join("-") ?? secret;
}

export function normalizeVoucher(value: string): string {
  return value.replaceAll("-", "").trim();
}

export function encryptOutboxPayload(value: unknown): string {
  const key = emailOutboxEncryptionKey().subarray(0, 32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  return [iv, cipher.getAuthTag(), ciphertext]
    .map((part) => part.toString("base64url"))
    .join(".");
}

export function decryptOutboxPayload(value: string): unknown {
  const [ivValue, tagValue, ciphertextValue] = value.split(".");
  if (!ivValue || !tagValue || !ciphertextValue)
    throw new Error("Invalid encrypted payload.");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    emailOutboxEncryptionKey().subarray(0, 32),
    Buffer.from(ivValue, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return JSON.parse(
    Buffer.concat([
      decipher.update(Buffer.from(ciphertextValue, "base64url")),
      decipher.final(),
    ]).toString("utf8"),
  ) as unknown;
}
