import { describe, expect, it } from "vitest";

import { digestSecret, secretDigestMatches } from "./secret-digest";

const testKey = Buffer.alloc(32, 7);

describe("domain-separated secret digests", () => {
  it("is deterministic within a domain and distinct across domains", () => {
    const session = digestSecret("session", "opaque-secret", testKey);
    const reset = digestSecret("password-reset", "opaque-secret", testKey);

    expect(session).toMatch(/^[0-9a-f]{64}$/);
    expect(session).toBe(digestSecret("session", "opaque-secret", testKey));
    expect(session).not.toBe(reset);
  });

  it("compares only canonical digests", () => {
    const digest = digestSecret("rate-limit", "staff", testKey);
    expect(secretDigestMatches(digest, digest)).toBe(true);
    expect(secretDigestMatches(digest, "invalid")).toBe(false);
  });

  it("rejects undersized digest keys", () => {
    expect(() =>
      digestSecret("session", "opaque-secret", Buffer.alloc(31)),
    ).toThrow("at least 32 bytes");
  });
});
