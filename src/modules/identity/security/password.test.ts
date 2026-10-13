import { describe, expect, it } from "vitest";

import {
  hashPassword,
  passwordHashNeedsRehash,
  verifyPassword,
} from "./password";

describe("Argon2id password protection", () => {
  it("hashes with the approved parameters and verifies without retaining plaintext", async () => {
    const password = "four quiet lamps";
    const passwordHash = await hashPassword(password);

    expect(passwordHash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
    expect(passwordHash).not.toContain(password);
    await expect(verifyPassword(passwordHash, password)).resolves.toBe(true);
    await expect(
      verifyPassword(passwordHash, "incorrect password"),
    ).resolves.toBe(false);
    expect(passwordHashNeedsRehash(passwordHash)).toBe(false);
  });

  it("fails closed for malformed hashes", async () => {
    await expect(
      verifyPassword("not-a-hash", "four quiet lamps"),
    ).resolves.toBe(false);
    expect(passwordHashNeedsRehash("not-a-hash")).toBe(true);
  });
});
