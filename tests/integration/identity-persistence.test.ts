import { randomUUID } from "node:crypto";

import { Prisma, PrismaClient } from "@prisma/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  INITIAL_PERMISSIONS,
  INITIAL_ROLES,
} from "../../src/modules/identity/domain/catalog";
import { seedInitialIdentityCatalog } from "../../src/modules/identity/infrastructure/catalog-repository";

const testDatabaseUrl = process.env.TEST_DATABASE_URL;
const testMigrationDatabaseUrl = process.env.TEST_MIGRATION_DATABASE_URL;
if (!testDatabaseUrl || !testMigrationDatabaseUrl) {
  throw new Error(
    "TEST_DATABASE_URL and TEST_MIGRATION_DATABASE_URL are required for PostgreSQL integration tests.",
  );
}

const prisma = new PrismaClient({ datasourceUrl: testDatabaseUrl });
const migrationPrisma = new PrismaClient({
  datasourceUrl: testMigrationDatabaseUrl,
});
const validPasswordHash =
  "$argon2id$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$ZmFrZWhhc2hmaWVsZGZvcnRlc3Rz";

beforeAll(async () => {
  await Promise.all([prisma.$connect(), migrationPrisma.$connect()]);
});

afterAll(async () => {
  await Promise.all([prisma.$disconnect(), migrationPrisma.$disconnect()]);
});

describe("identity catalogue persistence", () => {
  it("seeds roles, permissions, and grants idempotently", async () => {
    await seedInitialIdentityCatalog(migrationPrisma);
    const first = await catalogueCounts();
    await seedInitialIdentityCatalog(migrationPrisma);
    const second = await catalogueCounts();

    expect(second).toEqual(first);
    expect(first.roles).toBe(5);
    expect(first.permissions).toBe(22);
    expect(first.grants).toBeGreaterThan(20);
  });

  it("keeps protected capability classification immutable", async () => {
    await seedInitialIdentityCatalog(migrationPrisma);

    await expect(
      migrationPrisma.permission.update({
        where: { code: "users:manage_super_admin" },
        data: { requiresSuperAdmin: false },
      }),
    ).rejects.toThrow("permission security fields are immutable");

    await expect(
      migrationPrisma.role.update({
        where: { code: "super_administrator" },
        data: { isProtected: false },
      }),
    ).rejects.toThrow("role security fields are immutable");

    const [administrator, protectedPermission] = await Promise.all([
      prisma.role.findUniqueOrThrow({ where: { code: "administrator" } }),
      prisma.permission.findUniqueOrThrow({
        where: { code: "users:manage_super_admin" },
      }),
    ]);
    await expect(
      prisma.rolePermission.create({
        data: {
          roleId: administrator.id,
          permissionId: protectedPermission.id,
        },
      }),
    ).rejects.toThrow("protected capabilities require a protected role");

    await expect(
      prisma.role.create({
        data: {
          code: `protected_${randomUUID().slice(0, 8)}`,
          name: "Invalid Protected Role",
          isSystem: true,
          isProtected: true,
        },
      }),
    ).rejects.toThrow();

    const superAdministrator = await prisma.role.findUniqueOrThrow({
      where: { code: "super_administrator" },
      include: { permissions: { take: 1 } },
    });
    await expect(
      prisma.rolePermission.delete({
        where: {
          roleId_permissionId: {
            roleId: superAdministrator.id,
            permissionId: superAdministrator.permissions[0].permissionId,
          },
        },
      }),
    ).rejects.toThrow("protected capability grants are immutable");
  });

  it("denies runtime catalogue escalation and preserves migration-owner updates", async () => {
    await seedInitialIdentityCatalog(migrationPrisma);
    const suffix = randomUUID().slice(0, 8);
    const superAdministrator = await prisma.role.findUniqueOrThrow({
      where: { code: "super_administrator" },
    });

    await expect(
      prisma.role.update({
        where: { id: superAdministrator.id },
        data: { isActive: false },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.role.create({
        data: {
          code: `runtime_system_${suffix}`,
          name: "Forbidden Runtime System Role",
          isSystem: true,
        },
      }),
    ).rejects.toThrow();

    const configurableRole = await prisma.role.create({
      data: {
        code: `runtime_role_${suffix}`,
        name: "Runtime Configurable Role",
      },
    });
    await expect(
      prisma.role.update({
        where: { id: configurableRole.id },
        data: { isSystem: true },
      }),
    ).rejects.toThrow();
    const reviewedSystemRole = await migrationPrisma.role.create({
      data: {
        code: `migration_system_${suffix}`,
        name: "Reviewed Migration System Role",
        isSystem: true,
      },
    });

    expect(configurableRole.isSystem).toBe(false);
    expect(reviewedSystemRole.isSystem).toBe(true);
    await expect(
      prisma.role.findUniqueOrThrow({ where: { id: superAdministrator.id } }),
    ).resolves.toMatchObject({ isActive: true });
    await expect(
      prisma.role.findUnique({ where: { code: `runtime_system_${suffix}` } }),
    ).resolves.toBeNull();
    await migrationPrisma.role.deleteMany({
      where: { id: { in: [configurableRole.id, reviewedSystemRole.id] } },
    });
  });

  it("atomically invalidates assigned users when role activity changes", async () => {
    const suffix = randomUUID().slice(0, 8);
    const role = await prisma.role.create({
      data: { code: `activity_${suffix}`, name: "Activity Test Role" },
    });
    const activeUsername = `active.role.${suffix}`;
    const inactiveUsername = `inactive.role.${suffix}`;
    const [activeUser, inactiveUser] = await Promise.all([
      prisma.user.create({
        data: {
          username: activeUsername,
          usernameNormalized: activeUsername,
          displayName: "Active Role User",
          status: "ACTIVE",
          passwordHash: validPasswordHash,
        },
      }),
      prisma.user.create({
        data: {
          username: inactiveUsername,
          usernameNormalized: inactiveUsername,
          displayName: "Inactive Role User",
          status: "INACTIVE",
        },
      }),
    ]);
    await prisma.userRole.createMany({
      data: [
        { userId: activeUser.id, roleId: role.id },
        { userId: inactiveUser.id, roleId: role.id },
      ],
    });
    const before = await userAuthorizationVersions([
      activeUser.id,
      inactiveUser.id,
    ]);

    await prisma.role.update({
      where: { id: role.id },
      data: { isActive: false },
    });
    const after = await userAuthorizationVersions([
      activeUser.id,
      inactiveUser.id,
    ]);
    expect(after.get(activeUser.id)).toBe(before.get(activeUser.id)! + 1);
    expect(after.get(inactiveUser.id)).toBe(inactiveUser.authzVersion + 1);

    await expect(
      prisma.$transaction(async (transaction) => {
        await transaction.role.update({
          where: { id: role.id },
          data: { isActive: true },
        });
        throw new Error("force role-activity rollback");
      }),
    ).rejects.toThrow("force role-activity rollback");

    const rolledBackRole = await prisma.role.findUniqueOrThrow({
      where: { id: role.id },
    });
    const rolledBackVersions = await userAuthorizationVersions([
      activeUser.id,
      inactiveUser.id,
    ]);
    expect(rolledBackRole.isActive).toBe(false);
    expect(rolledBackVersions).toEqual(after);

    await migrationPrisma.userRole.deleteMany({ where: { roleId: role.id } });
    await migrationPrisma.user.deleteMany({
      where: { id: { in: [activeUser.id, inactiveUser.id] } },
    });
    await migrationPrisma.role.delete({ where: { id: role.id } });
  });

  it("invalidates every affected active user in the permission transaction", async () => {
    await seedInitialIdentityCatalog(migrationPrisma);
    const administrator = await prisma.role.findUniqueOrThrow({
      where: { code: "administrator" },
    });
    const suffix = randomUUID().slice(0, 8);
    const username = `authz.${suffix}`;
    const user = await prisma.user.create({
      data: {
        username,
        usernameNormalized: username,
        displayName: "Authorization Version User",
        status: "ACTIVE",
        passwordHash: validPasswordHash,
      },
    });
    await prisma.userRole.create({
      data: { userId: user.id, roleId: administrator.id },
    });
    const afterAssignment = await prisma.user.findUniqueOrThrow({
      where: { id: user.id },
    });

    const permission = await migrationPrisma.permission.create({
      data: {
        code: `test_${suffix}:read`,
        resource: `test_${suffix}`,
        action: "read",
        description: "Temporary integration-test permission.",
      },
    });
    await prisma.rolePermission.create({
      data: { roleId: administrator.id, permissionId: permission.id },
    });
    const afterPermissionChange = await prisma.user.findUniqueOrThrow({
      where: { id: user.id },
    });

    expect(afterAssignment.authzVersion).toBe(user.authzVersion + 1);
    expect(afterPermissionChange.authzVersion).toBe(
      afterAssignment.authzVersion + 1,
    );

    await prisma.rolePermission.delete({
      where: {
        roleId_permissionId: {
          roleId: administrator.id,
          permissionId: permission.id,
        },
      },
    });
    await prisma.userRole.delete({
      where: { userId_roleId: { userId: user.id, roleId: administrator.id } },
    });
    await migrationPrisma.permission.delete({ where: { id: permission.id } });
    await migrationPrisma.user.delete({ where: { id: user.id } });
  });
});

describe("user identity constraints", () => {
  it("permits multiple null emails and rejects case-equivalent normalized identifiers", async () => {
    const suffix = randomUUID().slice(0, 8);
    const firstUsername = `staff.${suffix}`;
    const secondUsername = `till.${suffix}`;

    const first = await prisma.user.create({
      data: {
        username: firstUsername,
        usernameNormalized: firstUsername,
        displayName: "First Test User",
      },
    });
    const second = await prisma.user.create({
      data: {
        username: secondUsername,
        usernameNormalized: secondUsername,
        displayName: "Second Test User",
      },
    });

    expect(first.email).toBeNull();
    expect(second.email).toBeNull();
    await expect(
      prisma.user.create({
        data: {
          username: firstUsername,
          usernameNormalized: firstUsername,
          displayName: "Duplicate Test User",
        },
      }),
    ).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);

    await migrationPrisma.user.deleteMany({
      where: { id: { in: [first.id, second.id] } },
    });
  });

  it("enforces case-insensitive uniqueness for non-null email", async () => {
    const suffix = randomUUID().slice(0, 8);
    const first = await prisma.user.create({
      data: {
        username: `email.a.${suffix}`,
        usernameNormalized: `email.a.${suffix}`,
        email: `Staff.${suffix}@Example.COM`,
        emailNormalized: `staff.${suffix}@example.com`,
        displayName: "Email User A",
      },
    });

    await expect(
      prisma.user.create({
        data: {
          username: `email.b.${suffix}`,
          usernameNormalized: `email.b.${suffix}`,
          email: `staff.${suffix}@example.com`,
          emailNormalized: `staff.${suffix}@example.com`,
          displayName: "Email User B",
        },
      }),
    ).rejects.toBeInstanceOf(Prisma.PrismaClientKnownRequestError);

    await migrationPrisma.user.delete({ where: { id: first.id } });
  });

  it("rejects email-shaped usernames at the database boundary", async () => {
    await expect(
      prisma.$executeRaw`
        INSERT INTO users (
          id, username, username_normalized, display_name, status, authz_version, created_at, updated_at
        ) VALUES (
          ${randomUUID()}::uuid, 'staff@example.com', 'staff@example.com', 'Ambiguous User',
          'PENDING_PASSWORD'::"UserStatus", 1, now(), now()
        )
      `,
    ).rejects.toThrow();
  });

  it("enforces password presence for active accounts", async () => {
    const username = `active.${randomUUID().slice(0, 8)}`;
    await expect(
      prisma.user.create({
        data: {
          username,
          usernameNormalized: username,
          displayName: "Invalid Active User",
          status: "ACTIVE",
        },
      }),
    ).rejects.toThrow();

    const activeUser = await prisma.user.create({
      data: {
        username,
        usernameNormalized: username,
        displayName: "Valid Active User",
        status: "ACTIVE",
        passwordHash: validPasswordHash,
      },
    });
    await migrationPrisma.user.delete({ where: { id: activeUser.id } });
  });
});

describe("security persistence", () => {
  it("enforces session digest and expiry constraints", async () => {
    const username = `session.${randomUUID().slice(0, 8)}`;
    const user = await prisma.user.create({
      data: {
        username,
        usernameNormalized: username,
        displayName: "Session User",
      },
    });

    await expect(
      prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: "not-a-digest".padEnd(64, "x"),
          authzVersion: 1,
          idleExpiresAt: new Date(Date.now() + 60_000),
          absoluteExpiresAt: new Date(Date.now() + 120_000),
        },
      }),
    ).rejects.toThrow();

    await migrationPrisma.user.delete({ where: { id: user.id } });
  });

  it("enforces 60-minute idle and 12-hour absolute session maxima", async () => {
    const username = `expiry.${randomUUID().slice(0, 8)}`;
    const user = await prisma.user.create({
      data: {
        username,
        usernameNormalized: username,
        displayName: "Expiry User",
      },
    });
    const createdAt = new Date();
    const valid = await prisma.session.create({
      data: {
        userId: user.id,
        tokenHash: testDigest(),
        authzVersion: 1,
        createdAt,
        lastSeenAt: createdAt,
        idleExpiresAt: new Date(createdAt.getTime() + 60 * 60_000),
        absoluteExpiresAt: new Date(createdAt.getTime() + 12 * 60 * 60_000),
      },
    });

    await expect(
      prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: testDigest(),
          authzVersion: 1,
          createdAt,
          lastSeenAt: createdAt,
          idleExpiresAt: new Date(createdAt.getTime() + 60 * 60_000 + 1),
          absoluteExpiresAt: new Date(createdAt.getTime() + 12 * 60 * 60_000),
        },
      }),
    ).rejects.toThrow();

    await expect(
      prisma.session.create({
        data: {
          userId: user.id,
          tokenHash: testDigest(),
          authzVersion: 1,
          createdAt,
          lastSeenAt: createdAt,
          idleExpiresAt: new Date(createdAt.getTime() + 60 * 60_000),
          absoluteExpiresAt: new Date(
            createdAt.getTime() + 12 * 60 * 60_000 + 1,
          ),
        },
      }),
    ).rejects.toThrow();

    await prisma.session.delete({ where: { id: valid.id } });
    await migrationPrisma.user.delete({ where: { id: user.id } });
  });

  it("enforces a 15-minute maximum for ordinary reset grants", async () => {
    const suffix = randomUUID().slice(0, 8);
    const requester = await prisma.user.create({
      data: {
        username: `requester.${suffix}`,
        usernameNormalized: `requester.${suffix}`,
        displayName: "Reset Requester",
      },
    });
    const subject = await prisma.user.create({
      data: {
        username: `subject.${suffix}`,
        usernameNormalized: `subject.${suffix}`,
        displayName: "Reset Subject",
      },
    });
    const createdAt = new Date();
    const grant = await prisma.passwordResetGrant.create({
      data: {
        userId: subject.id,
        requestedById: requester.id,
        tokenHash: testDigest(),
        purpose: "ADMINISTRATOR_RESET",
        createdAt,
        expiresAt: new Date(createdAt.getTime() + 15 * 60_000),
      },
    });

    await expect(
      prisma.passwordResetGrant.create({
        data: {
          userId: subject.id,
          requestedById: requester.id,
          tokenHash: testDigest(),
          purpose: "ADMINISTRATOR_RESET",
          createdAt,
          expiresAt: new Date(createdAt.getTime() + 15 * 60_000 + 1),
        },
      }),
    ).rejects.toThrow();

    await migrationPrisma.passwordResetGrant.delete({
      where: { id: grant.id },
    });
    await migrationPrisma.user.deleteMany({
      where: { id: { in: [requester.id, subject.id] } },
    });
  });

  it("makes audit events append-only", async () => {
    const auditEvent = await prisma.auditEvent.create({
      data: {
        eventType: "identity.test",
        outcome: "SUCCESS",
        correlationId: randomUUID(),
        metadata: { safe: true },
      },
    });

    await expect(
      migrationPrisma.auditEvent.update({
        where: { id: auditEvent.id },
        data: { outcome: "FAILURE" },
      }),
    ).rejects.toThrow("audit_events are append-only");
    await expect(
      migrationPrisma.auditEvent.delete({ where: { id: auditEvent.id } }),
    ).rejects.toThrow("audit_events are append-only");
    await expect(
      migrationPrisma.$executeRawUnsafe("TRUNCATE TABLE audit_events"),
    ).rejects.toThrow("audit_events are append-only");

    await expect(
      prisma.auditEvent.update({
        where: { id: auditEvent.id },
        data: { outcome: "FAILURE" },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.auditEvent.delete({ where: { id: auditEvent.id } }),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRawUnsafe("TRUNCATE TABLE audit_events"),
    ).rejects.toThrow();
  });

  it("enforces least-privilege runtime database access", async () => {
    await expect(
      prisma.permission.create({
        data: {
          code: "forbidden:create",
          resource: "forbidden",
          action: "create",
          description: "Must not be created by the runtime role.",
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRawUnsafe(
        "CREATE TABLE runtime_must_not_create (id integer)",
      ),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRawUnsafe(
        "CREATE TEMP TABLE runtime_temp_forbidden (id integer)",
      ),
    ).rejects.toThrow();

    const migrationRole = new URL(testMigrationDatabaseUrl).username;
    if (!/^[a-z][a-z0-9_]{2,62}$/.test(migrationRole)) {
      throw new Error("Unexpected migration database role name.");
    }
    await expect(
      prisma.$executeRawUnsafe(`SET ROLE "${migrationRole}"`),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRawUnsafe(
        'ALTER TABLE roles DISABLE TRIGGER "roles_catalog_guard"',
      ),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRawUnsafe("SET session_replication_role = replica"),
    ).rejects.toThrow();
  });

  it("rolls back a domain write when its audit write fails", async () => {
    const username = `rollback.${randomUUID().slice(0, 8)}`;
    const existingAudit = await prisma.auditEvent.findFirstOrThrow({
      where: { eventType: "identity.test" },
      orderBy: { createdAt: "desc" },
    });

    await expect(
      prisma.$transaction(async (transaction) => {
        await transaction.user.create({
          data: {
            username,
            usernameNormalized: username,
            displayName: "Rollback User",
          },
        });
        await transaction.auditEvent.update({
          where: { id: existingAudit.id },
          data: { outcome: "FAILURE" },
        });
      }),
    ).rejects.toThrow();

    await expect(
      prisma.user.findUnique({ where: { usernameNormalized: username } }),
    ).resolves.toBeNull();
  });
});

async function catalogueCounts(): Promise<{
  roles: number;
  permissions: number;
  grants: number;
}> {
  const [roles, permissions, grants] = await Promise.all([
    prisma.role.count({
      where: { code: { in: INITIAL_ROLES.map(({ code }) => code) } },
    }),
    prisma.permission.count({
      where: { code: { in: INITIAL_PERMISSIONS.map(({ code }) => code) } },
    }),
    prisma.rolePermission.count({
      where: { role: { code: { in: INITIAL_ROLES.map(({ code }) => code) } } },
    }),
  ]);
  return { roles, permissions, grants };
}

async function userAuthorizationVersions(
  userIds: string[],
): Promise<Map<string, number>> {
  const users = await prisma.user.findMany({
    where: { id: { in: userIds } },
    select: { id: true, authzVersion: true },
  });
  return new Map(users.map(({ id, authzVersion }) => [id, authzVersion]));
}

function testDigest(): string {
  return randomUUID().replaceAll("-", "").repeat(2);
}
