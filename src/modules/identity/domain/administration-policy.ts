import type { Permission, Role, UserStatus } from "@prisma/client";
import { z } from "zod";

import { normalizeOptionalEmail, normalizeUsername } from "./identity-policy";

const safeText = (maximum: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(maximum)
    .refine((value) => !/[\u0000-\u001f\u007f]/.test(value), {
      message: "Control characters are not allowed.",
    });
const optionalText = (maximum: number) =>
  z
    .union([safeText(maximum), z.literal("")])
    .transform((value) => (value === "" ? null : value));
const idList = z.array(z.string().uuid()).max(100).transform(deduplicate);

export const createStaffSchema = z
  .object({
    username: z.string().max(320).transform(normalizeUsername),
    email: z
      .union([z.string().max(320), z.literal("")])
      .transform(normalizeOptionalEmail),
    displayName: safeText(120),
    roleIds: idList,
  })
  .strict();

export const updateStaffProfileSchema = z
  .object({
    userId: z.string().uuid(),
    displayName: safeText(120),
    email: z
      .union([z.string().max(320), z.literal("")])
      .transform(normalizeOptionalEmail),
    reason: optionalText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();

export const changeStaffStatusSchema = z
  .object({
    userId: z.string().uuid(),
    action: z.enum(["activate", "deactivate", "lock", "unlock"]),
    reason: optionalText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();

export const replaceUserRolesSchema = z
  .object({
    userId: z.string().uuid(),
    roleIds: idList,
    reason: optionalText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();

export const changeUsernameSchema = z
  .object({
    userId: z.string().uuid(),
    username: z.string().max(320).transform(normalizeUsername),
    reason: safeText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();

const roleCode = z.string().regex(/^[a-z][a-z0-9_]{1,79}$/);
export const createRoleSchema = z
  .object({
    code: roleCode,
    name: safeText(120),
    description: optionalText(500),
    permissionIds: idList,
  })
  .strict();
export const updateRoleSchema = z
  .object({
    roleId: z.string().uuid(),
    name: safeText(120),
    description: optionalText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();
export const changeRoleStatusSchema = z
  .object({
    roleId: z.string().uuid(),
    isActive: z.boolean(),
    reason: safeText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();
export const replaceRolePermissionsSchema = z
  .object({
    roleId: z.string().uuid(),
    permissionIds: idList,
    reason: optionalText(500),
    expectedUpdatedAt: z.coerce.date(),
  })
  .strict();

export const staffSearchSchema = z
  .object({
    query: z.string().trim().max(100).default(""),
    status: z
      .enum(["PENDING_PASSWORD", "ACTIVE", "INACTIVE", "LOCKED"])
      .optional(),
    cursor: z.string().uuid().optional(),
    limit: z.coerce.number().int().min(1).max(50).default(25),
  })
  .strict();

export class AdministrationPolicyError extends Error {
  constructor(
    readonly code:
      | "NOT_FOUND"
      | "FORBIDDEN"
      | "STALE"
      | "INVALID_TRANSITION"
      | "ENROLMENT_REQUIRED"
      | "REASON_REQUIRED"
      | "LAST_SUPER_ADMINISTRATOR",
    message: string,
  ) {
    super(message);
  }
}

export function nextStaffStatus(
  current: UserStatus,
  action: "activate" | "deactivate" | "lock" | "unlock",
  hasPassword: boolean,
): UserStatus {
  if (action === "activate") {
    if (!hasPassword)
      throw new AdministrationPolicyError(
        "ENROLMENT_REQUIRED",
        "Password enrollment is required before activation.",
      );
    if (current !== "INACTIVE") invalidTransition();
    return "ACTIVE";
  }
  if (action === "deactivate") {
    if (current === "INACTIVE") invalidTransition();
    return "INACTIVE";
  }
  if (action === "lock") {
    if (current !== "ACTIVE") invalidTransition();
    return "LOCKED";
  }
  if (current !== "LOCKED") invalidTransition();
  return hasPassword ? "ACTIVE" : "PENDING_PASSWORD";
}

export function isProtectedAccount(
  roles: readonly Pick<Role, "code" | "isProtected" | "isActive">[],
): boolean {
  return roles.some(
    (role) =>
      role.code === "super_administrator" && role.isProtected && role.isActive,
  );
}

export function isOperationalRole(
  role: Pick<Role, "code" | "isActive" | "isProtected"> & {
    permissions: readonly {
      permission: Pick<Permission, "requiresSuperAdmin">;
    }[];
  },
): boolean {
  return (
    role.isActive &&
    !role.isProtected &&
    role.code !== "administrator" &&
    role.code !== "super_administrator" &&
    role.permissions.every(({ permission }) => !permission.requiresSuperAdmin)
  );
}

function deduplicate(values: string[]): string[] {
  return [...new Set(values)];
}

function invalidTransition(): never {
  throw new AdministrationPolicyError(
    "INVALID_TRANSITION",
    "The requested account status transition is not allowed.",
  );
}
