import { describe, expect, it } from "vitest";

import {
  changeStaffStatusSchema,
  createStaffSchema,
  isOperationalRole,
  nextStaffStatus,
  updateStaffProfileSchema,
} from "./administration-policy";

describe("staff administration policy", () => {
  it("creates only normalized enrollment-ready input", () => {
    expect(
      createStaffSchema.parse({
        username: "  New.Staff ",
        email: " Staff@Example.test ",
        displayName: " New Staff ",
        roleIds: [],
      }),
    ).toMatchObject({
      username: "new.staff",
      email: "staff@example.test",
      displayName: "New Staff",
    });
  });

  it("rejects mass-assigned security fields", () => {
    expect(() =>
      updateStaffProfileSchema.parse({
        userId: "74eb05e9-4f6e-4c0d-b15d-8f17156c20df",
        displayName: "Staff",
        email: "",
        expectedUpdatedAt: new Date(),
        username: "forbidden",
        passwordHash: "forbidden",
        status: "ACTIVE",
      }),
    ).toThrow();
  });

  it("requires enrollment before activation and enforces transitions", () => {
    expect(
      changeStaffStatusSchema.parse({
        userId: "74eb05e9-4f6e-4c0d-b15d-8f17156c20df",
        action: "activate",
        reason: "",
        expectedUpdatedAt: new Date(),
      }).reason,
    ).toBeNull();
    expect(() => nextStaffStatus("INACTIVE", "activate", false)).toThrow(
      "Password enrollment",
    );
    expect(nextStaffStatus("INACTIVE", "activate", true)).toBe("ACTIVE");
    expect(nextStaffStatus("LOCKED", "unlock", false)).toBe("PENDING_PASSWORD");
    expect(() => nextStaffStatus("PENDING_PASSWORD", "lock", false)).toThrow();
  });

  it("classifies only active non-administrator non-privileged roles as operational", () => {
    const base = {
      code: "cashier",
      isSystem: true,
      isActive: true,
      isProtected: false,
      permissions: [
        {
          permission: {
            code: "dashboard:view",
            requiresSuperAdmin: false,
          },
        },
      ],
    };
    expect(isOperationalRole(base)).toBe(true);
    expect(isOperationalRole({ ...base, code: "administrator" })).toBe(false);
    expect(
      isOperationalRole({
        ...base,
        isSystem: false,
        code: "custom_operations",
        permissions: [
          {
            permission: {
              code: "users:update",
              requiresSuperAdmin: false,
            },
          },
        ],
      }),
    ).toBe(false);
    expect(
      isOperationalRole({
        ...base,
        isSystem: false,
        code: "mixed_custom",
        permissions: [
          ...base.permissions,
          {
            permission: {
              code: "roles:assign",
              requiresSuperAdmin: false,
            },
          },
        ],
      }),
    ).toBe(false);
    expect(
      isOperationalRole({
        ...base,
        isSystem: false,
        code: "custom_dashboard",
      }),
    ).toBe(true);
  });
});
