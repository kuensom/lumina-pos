import { describe, expect, it } from "vitest";
import { validateIdentitySet } from "./database-identity-policy.mjs";

const server = { host: "172.18.0.2", port: 5432, connectionHost: "127.0.0.1" };
const valid = {
  primary: { ...server, database: "lumina_pos_dev", user: "migrator" },
  runtime: { ...server, database: "lumina_pos_dev", user: "runtime" },
  shadow: { ...server, database: "lumina_pos_shadow", user: "migrator" },
};

describe("database identity policy", () => {
  it("accepts approved local separation", () =>
    expect(() => validateIdentitySet(valid)).not.toThrow());
  it("rejects a shadow resolving to the primary despite different credentials", () =>
    expect(() =>
      validateIdentitySet({
        ...valid,
        shadow: { ...valid.shadow, database: "lumina_pos_dev", user: "other" },
      }),
    ).toThrow(/shadow database/i));
  it.each(["production", "lumina_staging", "other_database"])(
    "rejects unapproved shadow %s",
    (database) =>
      expect(() =>
        validateIdentitySet({
          ...valid,
          shadow: { ...valid.shadow, database },
        }),
      ).toThrow(),
  );
  it("rejects remote connections and shared roles", () => {
    expect(() =>
      validateIdentitySet({
        ...valid,
        shadow: { ...valid.shadow, connectionHost: "db.example.test" },
      }),
    ).toThrow(/local PostgreSQL/i);
    expect(() =>
      validateIdentitySet({
        ...valid,
        runtime: { ...valid.runtime, user: "migrator" },
      }),
    ).toThrow(/distinct/i);
  });
  it("rejects reset operations against protected databases", () => {
    expect(() => validateIdentitySet({ ...valid, operation: "reset" })).toThrow(
      /reset commands are prohibited/i,
    );
  });
  it("requires a distinct approved rollback database", () => {
    expect(() =>
      validateIdentitySet({ ...valid, operation: "rollback" }),
    ).toThrow(/rollback database identity is required/i);
    expect(() =>
      validateIdentitySet({
        ...valid,
        operation: "rollback",
        rollback: {
          ...valid.primary,
          database: "lumina_pos_b4_rollback_test",
        },
      }),
    ).not.toThrow();
    expect(() =>
      validateIdentitySet({
        ...valid,
        operation: "rollback",
        rollback: valid.primary,
      }),
    ).toThrow();
  });
  it("accepts the isolated CI identity profile", () => {
    expect(() =>
      validateIdentitySet({
        context: "ci",
        operation: "drift",
        primary: { ...server, database: "lumina_ci", user: "ci_migrator" },
        runtime: { ...server, database: "lumina_ci", user: "ci_runtime" },
        shadow: {
          ...server,
          database: "lumina_ci_shadow",
          user: "ci_migrator",
        },
      }),
    ).not.toThrow();
  });
});
