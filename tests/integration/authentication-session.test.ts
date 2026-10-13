import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { authenticateCredentials } from "../../src/modules/identity/application/authenticate-credentials";
import { revokeSessionForLogout } from "../../src/modules/identity/application/revoke-session";
import { seedInitialIdentityCatalog } from "../../src/modules/identity/infrastructure/catalog-repository";
import {
  isLoginRateLimited,
  recordLoginFailure,
} from "../../src/modules/identity/infrastructure/authentication-repository";
import { hashPassword } from "../../src/modules/identity/security/password";
import { rateLimitDigestKey } from "../../src/modules/identity/security/auth-secrets";
import { digestSecret } from "../../src/modules/identity/security/secret-digest";
import {
  AuthenticationRequiredError,
  PermissionDeniedError,
  RecentAuthenticationRequiredError,
  authenticateRequest,
  requirePermission,
  requireSuperAdministrator,
  withAuthorizedTransaction,
} from "../../src/modules/identity/server/guards";

const runtimeUrl = process.env.TEST_DATABASE_URL;
const migrationUrl = process.env.TEST_MIGRATION_DATABASE_URL;
if (!runtimeUrl || !migrationUrl) {
  throw new Error(
    "TEST_DATABASE_URL and TEST_MIGRATION_DATABASE_URL are required.",
  );
}
if (!process.env.SESSION_DIGEST_KEY || !process.env.RATE_LIMIT_DIGEST_KEY) {
  throw new Error("Authentication digest keys are required.");
}

const prisma = new PrismaClient({ datasourceUrl: runtimeUrl });
const migrationPrisma = new PrismaClient({ datasourceUrl: migrationUrl });
const createdUserIds: string[] = [];

beforeAll(async () => {
  await Promise.all([prisma.$connect(), migrationPrisma.$connect()]);
  await seedInitialIdentityCatalog(migrationPrisma);
});

afterAll(async () => {
  if (createdUserIds.length > 0) {
    await migrationPrisma.session.deleteMany({
      where: { userId: { in: createdUserIds } },
    });
    await migrationPrisma.userRole.deleteMany({
      where: { userId: { in: createdUserIds } },
    });
    await migrationPrisma.user.updateMany({
      where: { id: { in: createdUserIds } },
      data: { status: "INACTIVE", passwordHash: null },
    });
  }
  await Promise.all([prisma.$disconnect(), migrationPrisma.$disconnect()]);
});

describe("credentials authentication", () => {
  it("supports username and optional email with independent device sessions", async () => {
    const fixture = await createActiveUser({ withEmail: true });
    const [first, second] = await Promise.all([
      login(fixture.username, fixture.password),
      login(fixture.email!, fixture.password),
    ]);

    expect(first).not.toBeNull();
    expect(second).not.toBeNull();
    expect(first!.sessionId).not.toBe(second!.sessionId);
    const sessions = await prisma.session.findMany({
      where: { userId: fixture.id },
    });
    expect(sessions).toHaveLength(2);
    expect(
      sessions.every(({ tokenHash }) => /^[0-9a-f]{64}$/.test(tokenHash)),
    ).toBe(true);
    expect(JSON.stringify(sessions)).not.toContain(first!.sessionBinding);
    expect(JSON.stringify(sessions)).not.toContain(fixture.password);
    const successAudit = await prisma.auditEvent.findFirstOrThrow({
      where: { eventType: "identity.login_succeeded", actorUserId: fixture.id },
      orderBy: { createdAt: "desc" },
    });
    expect(JSON.stringify(successAudit)).not.toContain(first!.sessionBinding);
    expect(JSON.stringify(successAudit)).not.toContain(fixture.password);
  });

  it("returns the same failure for unknown, wrong, and inactive accounts", async () => {
    const fixture = await createActiveUser();
    const unknown = await login(
      `missing.${randomUUID().slice(0, 8)}`,
      fixture.password,
    );
    const wrong = await login(fixture.username, "wrong password value");
    await migrationPrisma.user.update({
      where: { id: fixture.id },
      data: { status: "INACTIVE" },
    });
    const inactive = await login(fixture.username, fixture.password);

    expect(unknown).toBeNull();
    expect(wrong).toBeNull();
    expect(inactive).toBeNull();
    const denied = await prisma.auditEvent.findMany({
      where: { eventType: "identity.login_denied" },
      orderBy: { createdAt: "desc" },
      take: 3,
    });
    expect(denied).toHaveLength(3);
    for (const event of denied) {
      expect(event.metadata).toMatchObject({ reason: "INVALID_CREDENTIALS" });
      expect(JSON.stringify(event.metadata)).not.toContain(fixture.password);
      expect(JSON.stringify(event.metadata)).not.toContain(fixture.username);
    }
  });

  it("blocks an identifier after five simultaneous failures", async () => {
    const fixture = await createActiveUser();
    await Promise.all(
      Array.from({ length: 5 }, () =>
        login(fixture.username, "wrong password value"),
      ),
    );
    await expect(login(fixture.username, fixture.password)).resolves.toBeNull();
    const bucket = await prisma.authRateLimitBucket.findFirstOrThrow({
      where: { scope: "LOGIN_IDENTIFIER" },
      orderBy: { updatedAt: "desc" },
    });
    expect(bucket.attempts).toBeGreaterThanOrEqual(5);
    expect(bucket.blockedUntil).not.toBeNull();
  });

  it("serializes a threshold failure ahead of concurrent valid admissions", async () => {
    const fixture = await createActiveUser();
    const now = new Date();
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await login(fixture.username, "wrong password value", now);
    }
    const identifierHash = digestSecret(
      "rate-limit",
      fixture.username,
      rateLimitDigestKey(),
    );
    const thresholdFailure = recordLoginFailure({
      prisma,
      identifierHash,
      networkHash: null,
      identifierKind: "username",
      now,
      correlationId: randomUUID(),
    });
    const validAdmissions = Array.from({ length: 6 }, () =>
      login(fixture.username, fixture.password, now),
    );

    const [, ...sessions] = await Promise.all([
      thresholdFailure,
      ...validAdmissions,
    ]);
    expect(sessions.every((session) => session === null)).toBe(true);
    await expect(
      prisma.session.count({ where: { userId: fixture.id } }),
    ).resolves.toBe(0);
  });

  it("bounds malformed credentials and suppresses blocked-attempt audit floods", async () => {
    const before = await prisma.auditEvent.count({
      where: { eventType: "identity.login_denied" },
    });
    await expect(
      authenticateCredentials({
        prisma,
        identifier: "x".repeat(321),
        password: "valid password value",
        headers: new Headers(),
      }),
    ).resolves.toBeNull();
    await expect(
      authenticateCredentials({
        prisma,
        identifier: "valid.user",
        password: "x".repeat(129),
        headers: new Headers(),
      }),
    ).resolves.toBeNull();
    expect(
      await prisma.auditEvent.count({
        where: { eventType: "identity.login_denied" },
      }),
    ).toBe(before);

    const malformed = `@${randomUUID().slice(0, 8)}`;
    await expect(login(malformed, "valid password value")).resolves.toBeNull();

    const fixture = await createActiveUser();
    for (let attempt = 0; attempt < 25; attempt += 1) {
      await login(fixture.username, "wrong password value");
    }
    const after = await prisma.auditEvent.count({
      where: { eventType: "identity.login_denied" },
    });
    expect(after - before).toBe(6);
    const identifierHash = digestSecret(
      "rate-limit",
      fixture.username,
      rateLimitDigestKey(),
    );
    const bucket = await prisma.authRateLimitBucket.findFirstOrThrow({
      where: { scope: "LOGIN_IDENTIFIER", subjectHash: identifierHash },
    });
    expect(bucket.attempts).toBe(5);
  });

  it("blocks a trusted network after thirty concurrent failures", async () => {
    const networkHash = randomUUID().replaceAll("-", "").repeat(2);
    const now = new Date();

    await Promise.all(
      Array.from({ length: 30 }, (_, index) =>
        recordLoginFailure({
          prisma,
          identifierHash: index.toString(16).padStart(64, "0"),
          networkHash,
          identifierKind: "invalid",
          now,
          correlationId: randomUUID(),
        }),
      ),
    );

    await expect(
      isLoginRateLimited(prisma, "unblocked-identifier", networkHash, now),
    ).resolves.toBe(true);
    const bucket = await prisma.authRateLimitBucket.findFirstOrThrow({
      where: { scope: "LOGIN_NETWORK", subjectHash: networkHash },
    });
    expect(bucket.attempts).toBe(30);
    expect(bucket.blockedUntil).not.toBeNull();
    await expect(
      isLoginRateLimited(prisma, "unblocked-identifier", "f".repeat(64), now),
    ).resolves.toBe(false);
  });
});

describe("authoritative session and authorization guards", () => {
  it("refreshes only authorized activity and enforces idle and absolute expiry", async () => {
    const base = new Date("2026-10-13T01:00:00.000Z");
    const fixture = await createActiveUser({ roleCode: "cashier" });
    const session = await login(fixture.username, fixture.password, base);
    expect(session).not.toBeNull();

    const before = await prisma.session.findUniqueOrThrow({
      where: { id: session!.sessionId },
    });
    await authenticateRequest({
      prisma,
      claims: session,
      now: new Date(base.getTime() + 5 * 60_000),
    });
    const afterAuthenticationOnly = await prisma.session.findUniqueOrThrow({
      where: { id: session!.sessionId },
    });
    expect(afterAuthenticationOnly.lastSeenAt).toEqual(before.lastSeenAt);
    await expect(
      requirePermission({
        prisma,
        claims: session,
        permission: "users:create",
        refreshActivity: true,
        now: new Date(base.getTime() + 10 * 60_000),
      }),
    ).rejects.toBeInstanceOf(PermissionDeniedError);
    const afterDenied = await prisma.session.findUniqueOrThrow({
      where: { id: session!.sessionId },
    });
    expect(afterDenied.lastSeenAt).toEqual(before.lastSeenAt);

    const activityAt = new Date(base.getTime() + 20 * 60_000);
    await requirePermission({
      prisma,
      claims: session,
      permission: "dashboard:view",
      refreshActivity: true,
      now: activityAt,
    });
    const afterAllowed = await prisma.session.findUniqueOrThrow({
      where: { id: session!.sessionId },
    });
    expect(afterAllowed.lastSeenAt).toEqual(activityAt);
    expect(afterAllowed.absoluteExpiresAt).toEqual(before.absoluteExpiresAt);

    await expect(
      authenticateRequest({
        prisma,
        claims: session,
        now: new Date(activityAt.getTime() + 60 * 60_000 + 1),
      }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
    await expect(
      authenticateRequest({
        prisma,
        claims: session,
        now: new Date(base.getTime() + 12 * 60 * 60_000),
      }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
  });

  it("rejects revoked sessions and sessions invalidated by role changes", async () => {
    const logoutUser = await createActiveUser({ roleCode: "cashier" });
    const logoutSession = await login(logoutUser.username, logoutUser.password);
    await revokeSessionForLogout({ prisma, claims: logoutSession! });
    await expect(
      authenticateRequest({ prisma, claims: logoutSession }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);

    const changedUser = await createActiveUser({ roleCode: "cashier" });
    const changedSession = await login(
      changedUser.username,
      changedUser.password,
    );
    const cashier = await prisma.role.findUniqueOrThrow({
      where: { code: "cashier" },
    });
    await prisma.userRole.delete({
      where: {
        userId_roleId: { userId: changedUser.id, roleId: cashier.id },
      },
    });
    await expect(
      authenticateRequest({ prisma, claims: changedSession }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
  });

  it("does not report or persist logout when authoritative revocation fails", async () => {
    const fixture = await createActiveUser({ roleCode: "cashier" });
    const session = await login(fixture.username, fixture.password);
    await expect(
      revokeSessionForLogout({
        prisma,
        claims: { ...session!, sessionBinding: "invalid-binding" },
      }),
    ).rejects.toThrow("Invalid session.");
    await expect(
      prisma.session.findUniqueOrThrow({ where: { id: session!.sessionId } }),
    ).resolves.toMatchObject({ revokedAt: null });
    await expect(
      prisma.auditEvent.count({
        where: {
          actorUserId: fixture.id,
          eventType: "identity.logout",
          outcome: "SUCCESS",
        },
      }),
    ).resolves.toBe(0);
  });

  it("requires canonical Super Administrator membership and recent authentication", async () => {
    const fixture = await createActiveUser({ roleCode: "super_administrator" });
    const now = new Date();
    const session = await login(fixture.username, fixture.password, now);
    await expect(
      requireSuperAdministrator({ prisma, claims: session, now }),
    ).resolves.toMatchObject({ userId: fixture.id });
    await expect(
      requireSuperAdministrator({
        prisma,
        claims: session,
        now: new Date(now.getTime() + 5 * 60_000 + 1),
      }),
    ).rejects.toBeInstanceOf(RecentAuthenticationRequiredError);
  });

  it("executes authorization and a protected write in one transaction", async () => {
    const fixture = await createActiveUser({ roleCode: "cashier" });
    const session = await login(fixture.username, fixture.password);
    const eventType = `identity.protected_test_${randomUUID().slice(0, 8)}`;
    await withAuthorizedTransaction({
      prisma,
      claims: session,
      permission: "dashboard:view",
      operation: async (transaction, principal) => {
        await transaction.auditEvent.create({
          data: {
            actorUserId: principal.userId,
            eventType,
            outcome: "SUCCESS",
            correlationId: randomUUID(),
            metadata: { safe: true },
          },
        });
      },
    });
    await expect(
      prisma.auditEvent.findFirst({ where: { eventType } }),
    ).resolves.not.toBeNull();
  });

  it("serializes protected writes with concurrent role removal and revocation", async () => {
    const fixture = await createActiveUser({ roleCode: "cashier" });
    const session = await login(fixture.username, fixture.password);
    const cashier = await prisma.role.findUniqueOrThrow({
      where: { code: "cashier" },
    });
    const eventType = `identity.concurrent_test_${randomUUID().slice(0, 8)}`;
    let releaseOperation!: () => void;
    const operationMayFinish = new Promise<void>((resolve) => {
      releaseOperation = resolve;
    });
    let operationStarted!: () => void;
    const operationHasStarted = new Promise<void>((resolve) => {
      operationStarted = resolve;
    });

    const protectedWrite = withAuthorizedTransaction({
      prisma,
      claims: session,
      permission: "dashboard:view",
      operation: async (transaction, principal) => {
        operationStarted();
        await operationMayFinish;
        await transaction.auditEvent.create({
          data: {
            actorUserId: principal.userId,
            eventType,
            outcome: "SUCCESS",
            correlationId: randomUUID(),
          },
        });
      },
    });
    await operationHasStarted;

    const roleRemoval = prisma.userRole.delete({
      where: {
        userId_roleId: { userId: fixture.id, roleId: cashier.id },
      },
    });
    const revocation = revokeSessionForLogout({ prisma, claims: session! });
    releaseOperation();
    await protectedWrite;
    await Promise.all([roleRemoval, revocation]);

    await expect(
      prisma.auditEvent.findFirst({ where: { eventType } }),
    ).resolves.not.toBeNull();
    await expect(
      authenticateRequest({ prisma, claims: session }),
    ).rejects.toBeInstanceOf(AuthenticationRequiredError);
  });
});

async function createActiveUser(
  options: {
    withEmail?: boolean;
    roleCode?: string;
  } = {},
) {
  const suffix = randomUUID().slice(0, 8);
  const username = `auth.${suffix}`;
  const password = `valid password ${randomUUID()}`;
  const email = options.withEmail ? `auth.${suffix}@example.test` : null;
  const user = await prisma.user.create({
    data: {
      username,
      usernameNormalized: username,
      email,
      emailNormalized: email,
      displayName: `Authentication User ${suffix}`,
      status: "ACTIVE",
      passwordHash: await hashPassword(password),
    },
  });
  createdUserIds.push(user.id);
  if (options.roleCode) {
    const role = await prisma.role.findUniqueOrThrow({
      where: { code: options.roleCode },
    });
    await prisma.userRole.create({
      data: { userId: user.id, roleId: role.id },
    });
  }
  return { id: user.id, username, password, email };
}

async function login(identifier: string, password: string, now?: Date) {
  return authenticateCredentials({
    prisma,
    identifier,
    password,
    headers: new Headers({ "user-agent": "integration-test" }),
    now,
  });
}
