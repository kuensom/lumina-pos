import { randomBytes } from "node:crypto";

function readKey(name: "SESSION_DIGEST_KEY" | "RATE_LIMIT_DIGEST_KEY"): Buffer {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  const key = Buffer.from(value, "base64");
  if (key.byteLength < 32) {
    throw new Error(`${name} must be at least 32 bytes encoded as base64.`);
  }
  return key;
}

export function sessionDigestKey(): Buffer {
  return readKey("SESSION_DIGEST_KEY");
}

export function rateLimitDigestKey(): Buffer {
  return readKey("RATE_LIMIT_DIGEST_KEY");
}

export function generateOpaqueSessionBinding(): string {
  return randomBytes(32).toString("base64url");
}
