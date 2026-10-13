import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  createRole,
  createStaff,
  listStaff,
  replaceUserRoles,
  updateStaffProfile,
} from "../../src/modules/identity/application/administration-service";
import { authenticateCredentials } from "../../src/modules/identity/application/authenticate-credentials";
import { seedInitialIdentityCatalog } from "../../src/modules/identity/infrastructure/catalog-repository";
import { hashPassword } from "../../src/modules/identity/security/password";

const runtimeUrl = process.env.TEST_DATABASE_URL;
const migrationUrl = process.env.TEST_MIGRATION_DATABASE_URL;
if (!runtimeUrl || !migrationUrl)
  throw new Error("Integration database URLs are required.");

const prisma = new PrismaClient({ datasourceUrl: runtimeUrl });
const migration = new PrismaClient({ datasourceUrl: migrationUrl });
const createdUserIds: string[] = [];
const createdRoleIds: string[] = [];
let administrator: Awaited<ReturnType<typeof principal>>;
let superAdministrator: Awaited<ReturnType<typeof principal>>;

beforeAll(async () => {
  await Promise.all([prisma.$connect(), migration.$connect()]);
  await seedInitialIdentityCatalog(migration);
  administrator = await principal("administrator");
  superAdministrator = await principal("super_administrator");
});

afterAll(async () => {
  if (createdUserIds.length) {
    await migration.session.deleteMany({
      where: { userId: { in: createdUserIds } },
    });
    await migration.userRole.deleteMany({
      where: { userId: { in: createdUserIds } },
    });
    await migration.user.updateMany({
      where: { id: { in: createdUserIds } },
      data: { status: "INACTIVE", passwordHash: null },
    });
  }
  if (createdRoleIds.length) {
    await migration.rolePermission.deleteMany({
      where: { roleId: { in: createdRoleIds } },
    });
    await migration.role.deleteMany({ where: { id: { in: createdRoleIds } } });
  }
  await Promise.all([prisma.$disconnect(), migration.$disconnect()]);
});

describe("staff and role administration", () => {
  it("creates enrollment-ready staff without credentials and only operational roles", async () => {
    const cashier = await prisma.role.findUniqueOrThrow({
      where: { code: "cashier" },
    });
    const supervisor = await prisma.role.findUniqueOrThrow({
      where: { code: "supervisor" },
    });
    const suffix = randomUUID().slice(0, 8);
    const created = await createStaff({
      prisma,
      claims: administrator.claims,
      command: {
        username: `pending.${suffix}`,
        email: "",
        displayName: "Pending Staff",
        roleIds: [cashier.id, supervisor.id],
      },
    });
    createdUserIds.push(created.id);
    await expect(
      prisma.user.findUniqueOrThrow({ where: { id: created.id } }),
    ).resolves.toMatchObject({
      status: "PENDING_PASSWORD",
      passwordHash: null,
      email: null,
    });
    await expect(
      prisma.userRole.count({ where: { userId: created.id } }),
    ).resolves.toBe(2);
    const privileged = await prisma.role.findUniqueOrThrow({
      where: { code: "administrator" },
    });
    await expect(
      createStaff({
        prisma,
        claims: administrator.claims,
        command: {
          username: `forbidden.${suffix}`,
          email: "",
          displayName: "Forbidden Staff",
          roleIds: [privileged.id],
        },
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("limits supervisor projections and hides protected accounts", async () => {
    const supervisor = await principal("supervisor");
    const result = await listStaff({
      prisma,
      claims: supervisor.claims,
      search: {},
    });
    expect(result.viewer).toBe("supervisor");
    expect(result.staff.every((staff) => !("email" in staff))).toBe(true);
    expect(
      result.staff.some((staff) => staff.id === superAdministrator.userId),
    ).toBe(false);
  });

  it("revokes sessions and increments authorization version on profile changes", async () => {
    const target = await principal("cashier");
    const before = await prisma.user.findUniqueOrThrow({
      where: { id: target.userId },
    });
    await updateStaffProfile({
      prisma,
      claims: administrator.claims,
      authority: "ordinary",
      command: {
        userId: target.userId,
        displayName: "Updated Staff",
        email: `updated.${randomUUID().slice(0, 8)}@example.test`,
        reason: "",
        expectedUpdatedAt: before.updatedAt,
      },
    });
    const [after, session] = await Promise.all([
      prisma.user.findUniqueOrThrow({ where: { id: target.userId } }),
      prisma.session.findUniqueOrThrow({
        where: { id: target.claims.sessionId },
      }),
    ]);
    expect(after.authzVersion).toBeGreaterThan(before.authzVersion);
    expect(session.revokedAt).not.toBeNull();
  });

  it("prevents ordinary administrators assigning privileged roles", async () => {
    const target = await principal("cashier");
    const before = await prisma.user.findUniqueOrThrow({
      where: { id: target.userId },
    });
    const privileged = await prisma.role.findUniqueOrThrow({
      where: { code: "administrator" },
    });
    await expect(
      replaceUserRoles({
        prisma,
        claims: administrator.claims,
        authority: "ordinary",
        command: {
          userId: target.userId,
          roleIds: [privileged.id],
          reason: "Attempted escalation",
          expectedUpdatedAt: before.updatedAt,
        },
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("rejects stale profile commands without partial mutation", async () => {
    const target = await principal("cashier");
    const stale = await prisma.user.findUniqueOrThrow({
      where: { id: target.userId },
    });
    await migration.user.update({
      where: { id: target.userId },
      data: { displayName: "Concurrent edit" },
    });
    await expect(
      updateStaffProfile({
        prisma,
        claims: administrator.claims,
        authority: "ordinary",
        command: {
          userId: target.userId,
          displayName: "Stale overwrite",
          email: "",
          reason: "",
          expectedUpdatedAt: stale.updatedAt,
        },
      }),
    ).rejects.toMatchObject({ code: "STALE" });
    await expect(
      prisma.user.findUniqueOrThrow({ where: { id: target.userId } }),
    ).resolves.toMatchObject({ displayName: "Concurrent edit" });
  });

  it("rolls back a profile mutation when immutable audit insertion fails", async () => {
    const target = await principal("cashier");
    const before = await prisma.user.findUniqueOrThrow({
      where: { id: target.userId },
    });
    await migration.$executeRawUnsafe(`
      CREATE FUNCTION b3_test_reject_profile_audit() RETURNS trigger
      LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.event_type = 'identity.staff_profile_updated' THEN
          RAISE EXCEPTION 'forced audit failure';
        END IF;
        RETURN NEW;
      END $$
    `);
    await migration.$executeRawUnsafe(`
      CREATE TRIGGER b3_test_reject_profile_audit
      BEFORE INSERT ON audit_events FOR EACH ROW
      EXECUTE FUNCTION b3_test_reject_profile_audit()
    `);
    try {
      await expect(
        updateStaffProfile({
          prisma,
          claims: administrator.claims,
          authority: "ordinary",
          command: {
            userId: target.userId,
            displayName: "Must roll back",
            email: "",
            reason: "",
            expectedUpdatedAt: before.updatedAt,
          },
        }),
      ).rejects.toThrow("forced audit failure");
      const after = await prisma.user.findUniqueOrThrow({
        where: { id: target.userId },
      });
      expect(after.displayName).toBe(before.displayName);
      await expect(
        prisma.session.findUniqueOrThrow({
          where: { id: target.claims.sessionId },
        }),
      ).resolves.toMatchObject({ revokedAt: null });
    } finally {
      await migration.$executeRawUnsafe(
        "DROP TRIGGER IF EXISTS b3_test_reject_profile_audit ON audit_events",
      );
      await migration.$executeRawUnsafe(
        "DROP FUNCTION IF EXISTS b3_test_reject_profile_audit()",
      );
    }
  });

  it("rejects protected permissions on configurable roles", async () => {
    const protectedPermission = await prisma.permission.findUniqueOrThrow({
      where: { code: "users:manage_super_admin" },
    });
    await expect(
      createRole({
        prisma,
        claims: superAdministrator.claims,
        command: {
          code: `unsafe_${randomUUID().slice(0, 8)}`,
          name: "Unsafe role",
          description: "",
          permissionIds: [protectedPermission.id],
        },
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("enforces the last-active-Super-Administrator invariant for runtime writes", async () => {
    const otherSupers = await prisma.user.findMany({
      where: {
        id: { not: superAdministrator.userId },
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
      select: { id: true },
    });
    try {
      for (const other of otherSupers) {
        await migration.user.update({
          where: { id: other.id },
          data: { status: "INACTIVE" },
        });
      }
      await expect(
        prisma.user.update({
          where: { id: superAdministrator.userId },
          data: { status: "INACTIVE" },
        }),
      ).rejects.toThrow("last active Super Administrator");
    } finally {
      await migration.user.updateMany({
        where: { id: { in: otherSupers.map(({ id }) => id) } },
        data: { status: "ACTIVE" },
      });
    }
  });

  it("serializes concurrent attempts to remove all active Super Administrators", async () => {
    const protectedRole = await migration.role.findUniqueOrThrow({
      where: { code: "super_administrator" },
    });
    const pair = await Promise.all(
      ["first", "second"].map(async (label) => {
        const suffix = randomUUID().slice(0, 8);
        const user = await migration.user.create({
          data: {
            username: `concurrent.${label}.${suffix}`,
            usernameNormalized: `concurrent.${label}.${suffix}`,
            displayName: `Concurrent ${label}`,
            status: "ACTIVE",
            passwordHash: await hashPassword(`valid password ${randomUUID()}`),
            roles: { create: { roleId: protectedRole.id } },
          },
        });
        createdUserIds.push(user.id);
        return user;
      }),
    );
    const otherSupers = await migration.user.findMany({
      where: {
        id: { notIn: pair.map(({ id }) => id) },
        status: "ACTIVE",
        roles: { some: { roleId: protectedRole.id } },
      },
      select: { id: true },
    });
    try {
      await migration.user.updateMany({
        where: { id: { in: otherSupers.map(({ id }) => id) } },
        data: { status: "INACTIVE" },
      });
      const results = await Promise.allSettled(
        pair.map(({ id }) =>
          prisma.user.update({ where: { id }, data: { status: "INACTIVE" } }),
        ),
      );
      expect(
        results.filter(({ status }) => status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        results.filter(({ status }) => status === "rejected"),
      ).toHaveLength(1);
      await expect(
        prisma.user.count({
          where: { id: { in: pair.map(({ id }) => id) }, status: "ACTIVE" },
        }),
      ).resolves.toBe(1);
    } finally {
      await migration.user.updateMany({
        where: { id: { in: otherSupers.map(({ id }) => id) } },
        data: { status: "ACTIVE" },
      });
    }
  });
});

async function principal(roleCode: string) {
  const suffix = randomUUID().slice(0, 8);
  const username = `b3.${roleCode}.${suffix}`;
  const password = `valid password ${randomUUID()}`;
  const role = await prisma.role.findUniqueOrThrow({
    where: { code: roleCode },
  });
  const user = await prisma.user.create({
    data: {
      username,
      usernameNormalized: username,
      displayName: `B3 ${roleCode}`,
      status: "ACTIVE",
      passwordHash: await hashPassword(password),
      roles: { create: { roleId: role.id } },
    },
  });
  createdUserIds.push(user.id);
  const claims = await authenticateCredentials({
    prisma,
    identifier: username,
    password,
    headers: new Headers({ "user-agent": "b3-integration-test" }),
  });
  if (!claims) throw new Error("Unable to create an authenticated B3 fixture.");
  return { userId: user.id, claims };
}
