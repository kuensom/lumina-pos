import { randomUUID } from "node:crypto";

import { Prisma, type PrismaClient } from "@prisma/client";
import type { z } from "zod";

import {
  AdministrationPolicyError,
  changeRoleStatusSchema,
  changeStaffStatusSchema,
  changeUsernameSchema,
  createRoleSchema,
  createStaffSchema,
  isOperationalRole,
  isProtectedAccount,
  nextStaffStatus,
  replaceRolePermissionsSchema,
  replaceUserRolesSchema,
  staffSearchSchema,
  updateRoleSchema,
  updateStaffProfileSchema,
} from "../domain/administration-policy";
import type { AuthClaims } from "../server/auth-claims";
import {
  type AuthenticatedPrincipal,
  withAuthorizedTransaction,
} from "../server/guards";

type MutationContext<T> = {
  prisma: PrismaClient;
  claims: AuthClaims;
  command: T;
  now?: Date;
};
type Authority = "ordinary" | "protected";

const protectedRoleInclude = {
  role: {
    select: {
      id: true,
      code: true,
      name: true,
      isProtected: true,
      isActive: true,
    },
  },
} satisfies Prisma.UserRoleInclude;

export async function listStaff(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
  search: unknown;
}) {
  const search = staffSearchSchema.parse(input.search);
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: "users:read",
    operation: async (tx, principal) => {
      const viewer = await viewerKind(tx, principal.userId);
      const protectedFilter =
        viewer === "super_administrator"
          ? {}
          : {
              roles: {
                none: {
                  role: {
                    code: "super_administrator",
                    isProtected: true,
                    isActive: true,
                  },
                },
              },
            };
      const rows = await tx.user.findMany({
        where: {
          ...protectedFilter,
          ...(search.status ? { status: search.status } : {}),
          ...(search.query
            ? {
                OR: [
                  {
                    usernameNormalized: {
                      contains: search.query.toLowerCase(),
                    },
                  },
                  {
                    displayName: {
                      contains: search.query,
                      mode: Prisma.QueryMode.insensitive,
                    },
                  },
                  ...(viewer === "supervisor"
                    ? []
                    : [
                        {
                          emailNormalized: {
                            contains: search.query.toLowerCase(),
                          },
                        },
                      ]),
                ],
              }
            : {}),
        },
        orderBy: [{ usernameNormalized: "asc" }, { id: "asc" }],
        take: search.limit + 1,
        ...(search.cursor ? { cursor: { id: search.cursor }, skip: 1 } : {}),
        select: {
          id: true,
          username: true,
          displayName: true,
          status: true,
          email: viewer === "supervisor" ? false : true,
          updatedAt: true,
          roles: {
            where: { role: { isActive: true } },
            select: { role: { select: { id: true, code: true, name: true } } },
          },
        },
      });
      const hasMore = rows.length > search.limit;
      const page = rows.slice(0, search.limit);
      return {
        viewer,
        staff: page,
        nextCursor: hasMore ? page.at(-1)?.id : undefined,
      };
    },
  });
}

export async function getStaffDetail(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
  userId: string;
}) {
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: "users:read",
    operation: async (tx, principal) => {
      const viewer = await viewerKind(tx, principal.userId);
      const user = await tx.user.findUnique({
        where: { id: input.userId },
        include: { roles: { include: protectedRoleInclude } },
      });
      if (
        !user ||
        (viewer !== "super_administrator" && targetIsProtected(user))
      ) {
        throw notFound();
      }
      return {
        viewer,
        user: {
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          email: viewer === "supervisor" ? undefined : user.email,
          status: user.status,
          updatedAt: user.updatedAt,
          roles: user.roles.map(({ role }) => role),
        },
      };
    },
  });
}

export async function createStaff(
  input: MutationContext<z.input<typeof createStaffSchema>>,
) {
  const command = createStaffSchema.parse(input.command);
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: "users:create",
    now: input.now,
    operation: async (tx, principal) => {
      const roles = await loadRoles(tx, command.roleIds);
      if (roles.some((role) => !isOperationalRole(role))) forbidden();
      const user = await tx.user.create({
        data: {
          username: command.username,
          usernameNormalized: command.username,
          email: command.email,
          emailNormalized: command.email,
          displayName: command.displayName,
          status: "PENDING_PASSWORD",
          passwordHash: null,
          roles: {
            create: roles.map(({ id }) => ({
              roleId: id,
              assignedById: principal.userId,
            })),
          },
        },
      });
      await audit(tx, principal, "identity.staff_created", "user", user.id, {
        initialStatus: "PENDING_PASSWORD",
        roleCodes: roles.map(({ code }) => code),
        hasEmail: command.email !== null,
      });
      return { id: user.id };
    },
  });
}

export async function updateStaffProfile(
  input: MutationContext<z.input<typeof updateStaffProfileSchema>> & {
    authority: Authority;
  },
) {
  const command = updateStaffProfileSchema.parse(input.command);
  return authorizedMutation(input, {
    permission:
      input.authority === "protected"
        ? "users:manage_super_admin"
        : "users:update",
    operation: async (tx, principal, now) => {
      const target = await lockAndLoadUser(tx, command.userId);
      assertCurrent(command.expectedUpdatedAt, target.updatedAt);
      const isProtected = targetIsProtected(target);
      if (isProtected !== (input.authority === "protected")) {
        if (input.authority === "ordinary") throw notFound();
        forbidden();
      }
      if (isProtected && !command.reason) {
        reasonRequired("protected account changes");
      }
      await tx.user.update({
        where: { id: target.id },
        data: {
          displayName: command.displayName,
          email: command.email,
          emailNormalized: command.email,
          authzVersion: { increment: 1 },
        },
      });
      const revoked = await revokeSessions(
        tx,
        target.id,
        "PROFILE_CHANGED",
        now,
      );
      await audit(
        tx,
        principal,
        "identity.staff_profile_updated",
        "user",
        target.id,
        {
          changedFields: changedProfileFields(target, command),
          emailChanged: target.emailNormalized !== command.email,
          protectedAccount: isProtected,
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function changeStaffStatus(
  input: MutationContext<z.input<typeof changeStaffStatusSchema>> & {
    authority: Authority;
  },
) {
  const command = changeStaffStatusSchema.parse(input.command);
  const permission =
    input.authority === "protected"
      ? "users:manage_super_admin"
      : `users:${command.action}`;
  return authorizedMutation(input, {
    permission,
    operation: async (tx, principal, now) => {
      if (
        principal.userId === command.userId &&
        (command.action === "deactivate" || command.action === "lock")
      ) {
        forbidden("You cannot deactivate or lock your own account.");
      }
      if (input.authority === "protected") await lockProtectedInvariant(tx);
      const target = await lockAndLoadUser(tx, command.userId);
      assertCurrent(command.expectedUpdatedAt, target.updatedAt);
      const isProtected = targetIsProtected(target);
      if (isProtected !== (input.authority === "protected")) {
        if (input.authority === "ordinary") throw notFound();
        forbidden();
      }
      if (
        (isProtected ||
          command.action === "deactivate" ||
          command.action === "lock") &&
        !command.reason
      ) {
        reasonRequired("deactivation, locking, and protected account changes");
      }
      const nextStatus = nextStaffStatus(
        target.status,
        command.action,
        Boolean(target.passwordHash),
      );
      if (
        isProtected &&
        target.status === "ACTIVE" &&
        nextStatus !== "ACTIVE"
      ) {
        await assertAnotherActiveSuperAdministrator(tx, target.id);
      }
      await tx.user.update({
        where: { id: target.id },
        data: { status: nextStatus, authzVersion: { increment: 1 } },
      });
      const revoked = await revokeSessions(
        tx,
        target.id,
        "STATUS_CHANGED",
        now,
      );
      await audit(
        tx,
        principal,
        "identity.staff_status_changed",
        "user",
        target.id,
        {
          from: target.status,
          to: nextStatus,
          reason: command.reason,
          protectedAccount: isProtected,
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function replaceUserRoles(
  input: MutationContext<z.input<typeof replaceUserRolesSchema>> & {
    authority: Authority;
  },
) {
  const command = replaceUserRolesSchema.parse(input.command);
  return authorizedMutation(input, {
    permission:
      input.authority === "protected"
        ? "roles:assign_privileged"
        : "roles:assign",
    operation: async (tx, principal, now) => {
      if (input.authority === "protected") await lockProtectedInvariant(tx);
      const target = await lockAndLoadUser(tx, command.userId);
      assertCurrent(command.expectedUpdatedAt, target.updatedAt);
      if (input.authority === "ordinary" && targetIsProtected(target)) {
        throw notFound();
      }
      const requested = await loadRoles(tx, command.roleIds);
      const currentRoles = await loadRoles(
        tx,
        target.roles.map(({ role }) => role.id),
      );
      let desired = requested;
      if (input.authority === "ordinary") {
        if (requested.some((role) => !isOperationalRole(role))) forbidden();
        const retainedPrivileged = currentRoles.filter(
          (role) => !isOperationalRole(role),
        );
        desired = [...retainedPrivileged, ...requested];
      } else if (requested.some((role) => !role.isActive)) {
        forbidden("Inactive roles cannot be assigned.");
      }
      const before = new Map(currentRoles.map((role) => [role.id, role]));
      const after = new Map(desired.map((role) => [role.id, role]));
      const removed = [...before.values()].filter(({ id }) => !after.has(id));
      const added = [...after.values()].filter(({ id }) => !before.has(id));
      if (removed.length > 0 && !command.reason) reasonRequired();
      if (
        input.authority === "protected" &&
        added.length > 0 &&
        !command.reason
      ) {
        reasonRequired("protected role changes");
      }
      if (
        principal.userId === target.id &&
        removed.some(({ code }) =>
          ["administrator", "super_administrator"].includes(code),
        )
      ) {
        forbidden("You cannot remove your own privileged roles.");
      }
      if (
        target.status === "ACTIVE" &&
        removed.some(({ code }) => code === "super_administrator")
      ) {
        await assertAnotherActiveSuperAdministrator(tx, target.id);
      }
      if (removed.length === 0 && added.length === 0) return;
      await tx.userRole.deleteMany({
        where: {
          userId: target.id,
          roleId: { in: removed.map(({ id }) => id) },
        },
      });
      await tx.userRole.createMany({
        data: added.map(({ id }) => ({
          userId: target.id,
          roleId: id,
          assignedById: principal.userId,
        })),
      });
      const revoked = await revokeSessions(tx, target.id, "ROLES_CHANGED", now);
      await audit(
        tx,
        principal,
        "identity.user_roles_replaced",
        "user",
        target.id,
        {
          addedRoleCodes: added.map(({ code }) => code),
          removedRoleCodes: removed.map(({ code }) => code),
          reason: command.reason,
          protectedChange: [...added, ...removed].some(
            ({ code }) => code === "super_administrator",
          ),
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function changeUsername(
  input: MutationContext<z.input<typeof changeUsernameSchema>>,
) {
  const command = changeUsernameSchema.parse(input.command);
  return authorizedMutation(input, {
    permission: "users:manage_super_admin",
    operation: async (tx, principal, now) => {
      await lockProtectedInvariant(tx);
      const target = await lockAndLoadUser(tx, command.userId);
      assertCurrent(command.expectedUpdatedAt, target.updatedAt);
      await tx.user.update({
        where: { id: target.id },
        data: {
          username: command.username,
          usernameNormalized: command.username,
          authzVersion: { increment: 1 },
        },
      });
      const revoked = await revokeSessions(
        tx,
        target.id,
        "USERNAME_CHANGED",
        now,
      );
      await audit(
        tx,
        principal,
        "identity.username_changed",
        "user",
        target.id,
        {
          reason: command.reason,
          protectedAccount: targetIsProtected(target),
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function listRoles(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
}) {
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: "roles:read",
    operation: async (tx, principal) => ({
      viewer: await viewerKind(tx, principal.userId),
      roles: await tx.role.findMany({
        orderBy: [{ isProtected: "desc" }, { name: "asc" }],
        include: {
          permissions: { include: { permission: true } },
          _count: { select: { users: true } },
        },
      }),
      permissions: await tx.permission.findMany({ orderBy: { code: "asc" } }),
    }),
  });
}

export async function createRole(
  input: MutationContext<z.input<typeof createRoleSchema>>,
) {
  const command = createRoleSchema.parse(input.command);
  return authorizedMutation(input, {
    permission: "roles:create",
    operation: async (tx, principal) => {
      const permissions = await loadPermissions(tx, command.permissionIds);
      if (permissions.some(({ requiresSuperAdmin }) => requiresSuperAdmin))
        forbidden();
      const role = await tx.role.create({
        data: {
          code: command.code,
          name: command.name,
          description: command.description,
          isSystem: false,
          isProtected: false,
          permissions: {
            create: permissions.map(({ id }) => ({ permissionId: id })),
          },
        },
      });
      await audit(tx, principal, "identity.role_created", "role", role.id, {
        roleCode: role.code,
        permissionCodes: permissions.map(({ code }) => code),
      });
      return { id: role.id };
    },
  });
}

export async function updateRole(
  input: MutationContext<z.input<typeof updateRoleSchema>>,
) {
  const command = updateRoleSchema.parse(input.command);
  return authorizedMutation(input, {
    permission: "roles:update",
    operation: async (tx, principal) => {
      const role = await lockAndLoadRole(tx, command.roleId);
      assertConfigurableRole(role);
      assertCurrent(command.expectedUpdatedAt, role.updatedAt);
      await tx.role.update({
        where: { id: role.id },
        data: { name: command.name, description: command.description },
      });
      await audit(
        tx,
        principal,
        "identity.role_profile_updated",
        "role",
        role.id,
        {
          roleCode: role.code,
          changedFields: [
            ...(role.name === command.name ? [] : ["name"]),
            ...(role.description === command.description
              ? []
              : ["description"]),
          ],
        },
      );
    },
  });
}

export async function changeRoleStatus(
  input: MutationContext<z.input<typeof changeRoleStatusSchema>>,
) {
  const command = changeRoleStatusSchema.parse(input.command);
  return authorizedMutation(input, {
    permission: "roles:update",
    operation: async (tx, principal, now) => {
      const role = await lockAndLoadRole(tx, command.roleId);
      assertConfigurableRole(role);
      assertCurrent(command.expectedUpdatedAt, role.updatedAt);
      const userIds = role.users.map(({ userId }) => userId);
      await tx.role.update({
        where: { id: role.id },
        data: { isActive: command.isActive },
      });
      const revoked = await revokeSessionsForUsers(
        tx,
        userIds,
        "ROLE_STATUS_CHANGED",
        now,
      );
      await audit(
        tx,
        principal,
        "identity.role_status_changed",
        "role",
        role.id,
        {
          roleCode: role.code,
          from: role.isActive,
          to: command.isActive,
          reason: command.reason,
          affectedUsers: userIds.length,
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function replaceRolePermissions(
  input: MutationContext<z.input<typeof replaceRolePermissionsSchema>>,
) {
  const command = replaceRolePermissionsSchema.parse(input.command);
  return authorizedMutation(input, {
    permission: "permissions:assign",
    operation: async (tx, principal, now) => {
      const role = await lockAndLoadRole(tx, command.roleId);
      assertConfigurableRole(role);
      assertCurrent(command.expectedUpdatedAt, role.updatedAt);
      const permissions = await loadPermissions(tx, command.permissionIds);
      if (permissions.some(({ requiresSuperAdmin }) => requiresSuperAdmin))
        forbidden();
      const before = new Map(
        role.permissions.map(({ permission }) => [permission.id, permission]),
      );
      const after = new Map(
        permissions.map((permission) => [permission.id, permission]),
      );
      const removed = [...before.values()].filter(({ id }) => !after.has(id));
      const added = [...after.values()].filter(({ id }) => !before.has(id));
      if (removed.length > 0 && !command.reason) reasonRequired();
      if (removed.length === 0 && added.length === 0) return;
      const userIds = role.users.map(({ userId }) => userId);
      await tx.rolePermission.deleteMany({
        where: {
          roleId: role.id,
          permissionId: { in: removed.map(({ id }) => id) },
        },
      });
      await tx.rolePermission.createMany({
        data: added.map(({ id }) => ({ roleId: role.id, permissionId: id })),
      });
      const revoked = await revokeSessionsForUsers(
        tx,
        userIds,
        "ROLE_PERMISSIONS_CHANGED",
        now,
      );
      await audit(
        tx,
        principal,
        "identity.role_permissions_replaced",
        "role",
        role.id,
        {
          roleCode: role.code,
          addedPermissionCodes: added.map(({ code }) => code),
          removedPermissionCodes: removed.map(({ code }) => code),
          reason: command.reason,
          affectedUsers: userIds.length,
          revokedSessions: revoked,
        },
      );
    },
  });
}

export async function listAdministrationAudit(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
}) {
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: "audit:read",
    operation: async (tx, principal) => {
      const viewer = await viewerKind(tx, principal.userId);
      const full = viewer === "super_administrator";
      const events = await tx.auditEvent.findMany({
        where: full
          ? {}
          : {
              eventType: {
                in: [
                  "identity.staff_created",
                  "identity.staff_profile_updated",
                  "identity.staff_status_changed",
                  "identity.user_roles_replaced",
                  "identity.role_created",
                  "identity.role_profile_updated",
                  "identity.role_status_changed",
                ],
              },
            },
        orderBy: { createdAt: "desc" },
        take: 100,
      });
      return events.map((event) => ({
        id: event.id,
        eventType: event.eventType,
        outcome: event.outcome,
        targetType: event.targetType,
        targetId: full ? event.targetId : null,
        createdAt: event.createdAt,
        metadata: full ? event.metadata : null,
      }));
    },
  });
}

export async function recordProtectedAdministrationDenial(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
  targetType: "user" | "role";
  targetId: string | null;
  reasonCode: AdministrationPolicyError["code"];
}) {
  return authorizedMutation(input, {
    permission: "users:manage_super_admin",
    operation: async (tx, principal) => {
      await tx.auditEvent.create({
        data: {
          actorUserId: principal.userId,
          eventType: "identity.protected_change_denied",
          targetType: input.targetType,
          targetId: input.targetId,
          outcome: "DENIED",
          correlationId: randomUUID(),
          metadata: { reasonCode: input.reasonCode },
        },
      });
    },
  });
}

async function authorizedMutation<T>(
  input: { prisma: PrismaClient; claims: AuthClaims; now?: Date },
  options: {
    permission: string;
    operation: (
      tx: Prisma.TransactionClient,
      principal: AuthenticatedPrincipal,
      now: Date,
    ) => Promise<T>;
  },
): Promise<T> {
  const now = input.now ?? new Date();
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission: options.permission,
    now,
    operation: (tx, principal) => options.operation(tx, principal, now),
  });
}

async function viewerKind(tx: Prisma.TransactionClient, userId: string) {
  const roles = await tx.userRole.findMany({
    where: { userId, role: { isActive: true } },
    select: { role: { select: { code: true, isProtected: true } } },
  });
  if (
    roles.some(
      ({ role }) => role.code === "super_administrator" && role.isProtected,
    )
  ) {
    return "super_administrator" as const;
  }
  if (roles.some(({ role }) => role.code === "administrator")) {
    return "administrator" as const;
  }
  return "supervisor" as const;
}

async function lockAndLoadUser(tx: Prisma.TransactionClient, userId: string) {
  await tx.$queryRaw`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;
  const user = await tx.user.findUnique({
    where: { id: userId },
    include: { roles: { include: protectedRoleInclude } },
  });
  if (!user) throw notFound();
  return user;
}

async function lockAndLoadRole(tx: Prisma.TransactionClient, roleId: string) {
  await tx.$queryRaw`SELECT id FROM roles WHERE id = ${roleId}::uuid FOR UPDATE`;
  const role = await tx.role.findUnique({
    where: { id: roleId },
    include: {
      users: { select: { userId: true } },
      permissions: { include: { permission: true } },
    },
  });
  if (!role) throw notFound();
  return role;
}

async function loadRoles(tx: Prisma.TransactionClient, ids: readonly string[]) {
  const roles = await tx.role.findMany({
    where: { id: { in: [...ids] } },
    include: { permissions: { include: { permission: true } } },
    orderBy: { id: "asc" },
  });
  if (roles.length !== ids.length) throw notFound();
  return roles;
}

async function loadPermissions(
  tx: Prisma.TransactionClient,
  ids: readonly string[],
) {
  const permissions = await tx.permission.findMany({
    where: { id: { in: [...ids] } },
    orderBy: { id: "asc" },
  });
  if (permissions.length !== ids.length) throw notFound();
  return permissions;
}

function targetIsProtected(target: {
  roles: readonly {
    role: { code: string; isProtected: boolean; isActive: boolean };
  }[];
}) {
  return isProtectedAccount(target.roles.map(({ role }) => role));
}

function assertConfigurableRole(role: {
  isSystem: boolean;
  isProtected: boolean;
}) {
  if (role.isSystem || role.isProtected)
    forbidden("System roles are immutable.");
}

function assertCurrent(expected: Date, actual: Date) {
  if (expected.getTime() !== actual.getTime()) {
    throw new AdministrationPolicyError(
      "STALE",
      "This record changed. Reload it before saving.",
    );
  }
}

async function lockProtectedInvariant(tx: Prisma.TransactionClient) {
  await tx.$queryRaw`
    SELECT pg_advisory_xact_lock(
      hashtextextended('lumina:last-active-super-administrator', 0)
    )::text
  `;
}

async function assertAnotherActiveSuperAdministrator(
  tx: Prisma.TransactionClient,
  excludedUserId: string,
) {
  const count = await tx.user.count({
    where: {
      id: { not: excludedUserId },
      status: "ACTIVE",
      roles: {
        some: {
          role: {
            code: "super_administrator",
            isProtected: true,
            isActive: true,
          },
        },
      },
    },
  });
  if (count === 0) {
    throw new AdministrationPolicyError(
      "LAST_SUPER_ADMINISTRATOR",
      "The last active Super Administrator cannot be removed or disabled.",
    );
  }
}

async function revokeSessions(
  tx: Prisma.TransactionClient,
  userId: string,
  reason: string,
  now: Date,
) {
  return revokeSessionsForUsers(tx, [userId], reason, now);
}

async function revokeSessionsForUsers(
  tx: Prisma.TransactionClient,
  userIds: readonly string[],
  reason: string,
  now: Date,
) {
  if (userIds.length === 0) return 0;
  const result = await tx.session.updateMany({
    where: { userId: { in: [...userIds] }, revokedAt: null },
    data: { revokedAt: now, revokeReason: reason },
  });
  return result.count;
}

async function audit(
  tx: Prisma.TransactionClient,
  principal: AuthenticatedPrincipal,
  eventType: string,
  targetType: string,
  targetId: string,
  metadata: Prisma.InputJsonValue,
) {
  await tx.auditEvent.create({
    data: {
      actorUserId: principal.userId,
      eventType,
      targetType,
      targetId,
      outcome: "SUCCESS",
      correlationId: randomUUID(),
      metadata,
    },
  });
}

function changedProfileFields(
  before: { displayName: string; emailNormalized: string | null },
  after: { displayName: string; email: string | null },
) {
  return [
    ...(before.displayName === after.displayName ? [] : ["displayName"]),
    ...(before.emailNormalized === after.email ? [] : ["email"]),
  ];
}

function forbidden(
  message = "The requested operation is not permitted.",
): never {
  throw new AdministrationPolicyError("FORBIDDEN", message);
}

function notFound() {
  return new AdministrationPolicyError("NOT_FOUND", "Staff record not found.");
}

function reasonRequired(context = "removing access"): never {
  throw new AdministrationPolicyError(
    "REASON_REQUIRED",
    `A reason is required for ${context}.`,
  );
}
