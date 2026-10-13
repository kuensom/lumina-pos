import { describe, expect, it } from "vitest";

import {
  assertPasswordPolicy,
  isReservedUsername,
  normalizeOptionalEmail,
  normalizeUsername,
} from "./identity-policy";

describe("identity normalization", () => {
  it("normalizes an approved username to its canonical value", () => {
    expect(normalizeUsername("  Shop.Manager  ")).toBe("shop.manager");
  });

  it.each(["ab", "staff@example.com", "staff name", "འཛིན་སྐྱོང་"])(
    "rejects an invalid or ambiguous username: %s",
    (username) => {
      expect(() => normalizeUsername(username)).toThrow();
    },
  );

  it("rejects reserved identifiers case-insensitively", () => {
    expect(isReservedUsername("ADMIN")).toBe(true);
    expect(() => normalizeUsername("ADMIN")).toThrow("reserved");
  });

  it("normalizes optional email without provider-specific rewriting", () => {
    expect(normalizeOptionalEmail(" Staff+Till@Example.COM ")).toBe(
      "staff+till@example.com",
    );
    expect(normalizeOptionalEmail("  ")).toBeNull();
    expect(normalizeOptionalEmail(null)).toBeNull();
  });

  it("rejects invalid email", () => {
    expect(() => normalizeOptionalEmail("not-an-email")).toThrow();
  });
});

describe("password policy", () => {
  it("accepts 12 through 128 Unicode characters", () => {
    expect(() => assertPasswordPolicy("correct horse")).not.toThrow();
    expect(() => assertPasswordPolicy("🔐".repeat(128))).not.toThrow();
  });

  it("rejects passwords outside the length bounds", () => {
    expect(() => assertPasswordPolicy("short")).toThrow("between 12 and 128");
    expect(() => assertPasswordPolicy("x".repeat(129))).toThrow(
      "between 12 and 128",
    );
  });
});
