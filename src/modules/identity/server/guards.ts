import { Prisma, type PrismaClient } from "@prisma/client";

import { RECENT_AUTHENTICATION_MINUTES } from "../domain/session-policy";
import { retrySerializableTransaction } from "../infrastructure/serializable-retry";
import { sessionDigestKey } from "../security/auth-secrets";
import { digestSecret } from "../security/secret-digest";
import { authClaimsSchema, type AuthClaims } from "./auth-claims";

export type AuthenticatedPrincipal = {
  userId: string;
  sessionId: string;
  displayName: string;
  authzVersion: number;
  passwordVersion: number;
  signedInAt: Date;
  absoluteExpiresAt: Date;
};

export class AuthenticationRequiredError extends Error {
  readonly status = 401;
}

export class PermissionDeniedError extends Error {
  readonly status = 403;
}

export class RecentAuthenticationRequiredError extends PermissionDeniedError {}

export async function authenticateRequest(input: {
  prisma: PrismaClient;
  claims: unknown;
  now?: Date;
}): Promise<AuthenticatedPrincipal> {
  return input.prisma.$transaction((transaction) =>
    validateInTransaction(transaction, input.claims, input.now ?? new Date()),
  );
}

export async function requirePermission(input: {
  prisma: PrismaClient;
  claims: unknown;
  permission: string;
  refreshActivity?: boolean;
  now?: Date;
}): Promise<AuthenticatedPrincipal> {
  const now = input.now ?? new Date();
  return input.prisma.$transaction(async (transaction) => {
    const principal = await validateInTransaction(
      transaction,
      input.claims,
      now,
    );
    const permission = await effectivePermission(
      transaction,
      principal.userId,
      input.permission,
    );
    if (!permission) throw new PermissionDeniedError("Permission denied.");
    if (permission.requiresSuperAdmin) {
      await assertSuperAdministrator(transaction, principal.userId);
      assertRecentAuthentication(principal, now);
    }
    if (input.refreshActivity) {
      await refreshSessionActivity(transaction, principal.sessionId, now);
    }
    return principal;
  });
}

export async function requireSuperAdministrator(input: {
  prisma: PrismaClient;
  claims: unknown;
  refreshActivity?: boolean;
  now?: Date;
}): Promise<AuthenticatedPrincipal> {
  const now = input.now ?? new Date();
  return input.prisma.$transaction(async (transaction) => {
    const principal = await validateInTransaction(
      transaction,
      input.claims,
      now,
    );
    await assertSuperAdministrator(transaction, principal.userId);
    assertRecentAuthentication(principal, now);
    if (input.refreshActivity) {
      await refreshSessionActivity(transaction, principal.sessionId, now);
    }
    return principal;
  });
}

export async function withAuthorizedTransaction<T>(input: {
  prisma: PrismaClient;
  claims: unknown;
  permission: string;
  operation: (
    transaction: Prisma.TransactionClient,
    principal: AuthenticatedPrincipal,
  ) => Promise<T>;
  now?: Date;
}): Promise<T> {
  const now = input.now ?? new Date();
  return retrySerializableTransaction(() =>
    input.prisma.$transaction(
      async (transaction) => {
        const principal = await validateInTransaction(
          transaction,
          input.claims,
          now,
        );
        const permission = await effectivePermission(
          transaction,
          principal.userId,
          input.permission,
        );
        if (!permission) throw new PermissionDeniedError("Permission denied.");
        if (permission.requiresSuperAdmin) {
          await assertSuperAdministrator(transaction, principal.userId);
          assertRecentAuthentication(principal, now);
        }
        await refreshSessionActivity(transaction, principal.sessionId, now);
        return input.operation(transaction, principal);
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    ),
  );
}

export async function withAuthenticatedTransaction<T>(input: {
  prisma: PrismaClient;
  claims: unknown;
  operation: (
    transaction: Prisma.TransactionClient,
    principal: AuthenticatedPrincipal,
  ) => Promise<T>;
  now?: Date;
}): Promise<T> {
  const now = input.now ?? new Date();
  return retrySerializableTransaction(() =>
    input.prisma.$transaction(
      async (transaction) => {
        const principal = await validateInTransaction(
          transaction,
          input.claims,
          now,
        );
        return input.operation(transaction, principal);
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    ),
  );
}

async function validateInTransaction(
  transaction: Prisma.TransactionClient,
  untrustedClaims: unknown,
  now: Date,
): Promise<AuthenticatedPrincipal> {
  const result = authClaimsSchema.safeParse(untrustedClaims);
  if (!result.success)
    throw new AuthenticationRequiredError("Invalid session.");
  const claims = result.data;
  if (now.getTime() >= claims.absoluteExpiresAt) {
    throw new AuthenticationRequiredError("Expired session.");
  }

  await transaction.$queryRaw`
    SELECT id FROM sessions WHERE id = ${claims.sessionId}::uuid FOR UPDATE
  `;
  await transaction.$queryRaw`
    SELECT id FROM users WHERE id = ${claims.sub}::uuid FOR UPDATE
  `;
  const tokenHash = digestSecret(
    "session",
    claims.sessionBinding,
    sessionDigestKey(),
  );
  const [session, user] = await Promise.all([
    transaction.session.findUnique({ where: { id: claims.sessionId } }),
    transaction.user.findUnique({ where: { id: claims.sub } }),
  ]);

  if (
    !session ||
    !user ||
    session.userId !== user.id ||
    session.tokenHash !== tokenHash ||
    session.revokedAt ||
    user.status !== "ACTIVE" ||
    session.authzVersion !== user.authzVersion ||
    session.passwordVersion !== user.passwordVersion ||
    claims.passwordVersion !== user.passwordVersion ||
    claims.authzVersion !== user.authzVersion ||
    session.idleExpiresAt.getTime() <= now.getTime() ||
    session.absoluteExpiresAt.getTime() <= now.getTime() ||
    session.absoluteExpiresAt.getTime() !== claims.absoluteExpiresAt
  ) {
    throw new AuthenticationRequiredError("Invalid session.");
  }

  return principalFromClaims(claims);
}

async function effectivePermission(
  transaction: Prisma.TransactionClient,
  userId: string,
  permissionCode: string,
): Promise<{ requiresSuperAdmin: boolean } | null> {
  const membership = await transaction.userRole.findFirst({
    where: {
      userId,
      role: {
        isActive: true,
        permissions: { some: { permission: { code: permissionCode } } },
      },
    },
    select: {
      role: {
        select: {
          permissions: {
            where: { permission: { code: permissionCode } },
            select: { permission: { select: { requiresSuperAdmin: true } } },
            take: 1,
          },
        },
      },
    },
  });
  return membership?.role.permissions[0]?.permission ?? null;
}

async function assertSuperAdministrator(
  transaction: Prisma.TransactionClient,
  userId: string,
): Promise<void> {
  const membership = await transaction.userRole.findFirst({
    where: {
      userId,
      role: {
        code: "super_administrator",
        isProtected: true,
        isActive: true,
      },
    },
    select: { userId: true },
  });
  if (!membership) throw new PermissionDeniedError("Permission denied.");
}

function assertRecentAuthentication(
  principal: AuthenticatedPrincipal,
  now: Date,
): void {
  if (
    now.getTime() - principal.signedInAt.getTime() >
    RECENT_AUTHENTICATION_MINUTES * 60 * 1000
  ) {
    throw new RecentAuthenticationRequiredError(
      "Recent authentication required.",
    );
  }
}

async function refreshSessionActivity(
  transaction: Prisma.TransactionClient,
  sessionId: string,
  now: Date,
): Promise<void> {
  await transaction.$executeRaw`
    UPDATE sessions
    SET last_seen_at = ${now},
        idle_expires_at = LEAST(${now} + INTERVAL '60 minutes', absolute_expires_at)
    WHERE id = ${sessionId}::uuid
  `;
}

function principalFromClaims(claims: AuthClaims): AuthenticatedPrincipal {
  return {
    userId: claims.sub,
    sessionId: claims.sessionId,
    displayName: claims.displayName,
    authzVersion: claims.authzVersion,
    passwordVersion: claims.passwordVersion,
    signedInAt: new Date(claims.signedInAt),
    absoluteExpiresAt: new Date(claims.absoluteExpiresAt),
  };
}
