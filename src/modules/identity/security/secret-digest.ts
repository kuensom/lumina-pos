import { createHmac, timingSafeEqual } from "node:crypto";

export const SECRET_DIGEST_DOMAINS = [
  "session",
  "password-reset",
  "initial-enrolment",
  "protected-recovery",
  "rate-limit",
] as const;

export type SecretDigestDomain = (typeof SECRET_DIGEST_DOMAINS)[number];

export function digestSecret(
  domain: SecretDigestDomain,
  secret: string,
  digestKey: Uint8Array,
): string {
  if (digestKey.byteLength < 32) {
    throw new Error("Secret digest keys must contain at least 32 bytes.");
  }
  if (secret.length === 0) {
    throw new Error("Cannot digest an empty secret.");
  }

  return createHmac("sha256", digestKey)
    .update("lumina-pos\0", "utf8")
    .update(domain, "utf8")
    .update("\0", "utf8")
    .update(secret, "utf8")
    .digest("hex");
}

export function secretDigestMatches(
  expected: string,
  candidate: string,
): boolean {
  if (!/^[0-9a-f]{64}$/.test(expected) || !/^[0-9a-f]{64}$/.test(candidate)) {
    return false;
  }

  return timingSafeEqual(
    Buffer.from(expected, "hex"),
    Buffer.from(candidate, "hex"),
  );
}
