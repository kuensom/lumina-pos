import { describe, expect, it } from "vitest";

import { INITIAL_PERMISSIONS, INITIAL_ROLES } from "./catalog";

describe("identity catalogue", () => {
  it("has unique canonical permission and role codes", () => {
    expect(new Set(INITIAL_PERMISSIONS.map(({ code }) => code)).size).toBe(
      INITIAL_PERMISSIONS.length,
    );
    expect(new Set(INITIAL_ROLES.map(({ code }) => code)).size).toBe(
      INITIAL_ROLES.length,
    );
    for (const permission of INITIAL_PERMISSIONS) {
      expect(permission.code).toBe(
        `${permission.resource}:${permission.action}`,
      );
    }
  });

  it("grants every protected capability only to the protected super role", () => {
    const protectedCodes = new Set(
      INITIAL_PERMISSIONS.filter(
        ({ requiresSuperAdmin }) => requiresSuperAdmin,
      ).map(({ code }) => code),
    );

    for (const role of INITIAL_ROLES) {
      const protectedGrants = role.permissionCodes.filter((code) =>
        protectedCodes.has(code),
      );
      expect(protectedGrants.length > 0).toBe(
        role.code === "super_administrator",
      );
    }
  });

  it("does not seed future wholesale capabilities", () => {
    expect(
      INITIAL_PERMISSIONS.some(({ resource }) => resource === "wholesale"),
    ).toBe(false);
  });
});
