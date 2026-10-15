import { beforeEach, describe, expect, it } from "vitest";

import {
  decryptOutboxPayload,
  encryptOutboxPayload,
  formatVoucher,
  generateCredential,
  normalizeVoucher,
} from "./credential-secret";

describe("credential secrets", () => {
  beforeEach(() => {
    process.env.EMAIL_OUTBOX_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString(
      "base64",
    );
  });

  it("creates 256-bit URL-safe credentials and reversible display grouping", () => {
    const credential = generateCredential();
    expect(Buffer.from(credential, "hex")).toHaveLength(32);
    expect(normalizeVoucher(formatVoucher(credential))).toBe(credential);
  });

  it("stores authenticated ciphertext rather than plaintext", () => {
    const payload = {
      recipient: "staff@example.test",
      credential: generateCredential(),
    };
    const encrypted = encryptOutboxPayload(payload);
    expect(encrypted).not.toContain(payload.credential);
    expect(decryptOutboxPayload(encrypted)).toEqual(payload);
  });
});
