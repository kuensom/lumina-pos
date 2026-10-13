import { randomUUID } from "node:crypto";

import { Prisma, type PrismaClient } from "@prisma/client";

import {
  IDENTIFIER_FAILURE_LIMIT,
  NETWORK_FAILURE_LIMIT,
  rateLimitWindowStart,
  RATE_LIMIT_WINDOW_MINUTES,
  sessionExpiryFrom,
} from "../domain/session-policy";
import { digestSecret } from "../security/secret-digest";
import { retrySerializableTransaction } from "./serializable-retry";

type DbClient = PrismaClient | Prisma.TransactionClient;
type RateScope = "LOGIN_IDENTIFIER" | "LOGIN_NETWORK";

export type LoginCandidate = {
  id: string;
  displayName: string;
  passwordHash: string | null;
  status: "PENDING_PASSWORD" | "ACTIVE" | "INACTIVE" | "LOCKED";
  authzVersion: number;
};

export async function findLoginCandidate(
  db: DbClient,
  normalizedIdentifier: string,
  kind: "username" | "email",
): Promise<LoginCandidate | null> {
  return db.user.findFirst({
    where:
      kind === "email"
        ? { emailNormalized: normalizedIdentifier }
        : { usernameNormalized: normalizedIdentifier },
    select: {
      id: true,
      displayName: true,
      passwordHash: true,
      status: true,
      authzVersion: true,
    },
  });
}

export async function isLoginRateLimited(
  db: DbClient,
  identifierHash: string,
  networkHash: string | null,
  now: Date,
): Promise<boolean> {
  const subjects = [
    { scope: "LOGIN_IDENTIFIER" as const, subjectHash: identifierHash },
    ...(networkHash
      ? [{ scope: "LOGIN_NETWORK" as const, subjectHash: networkHash }]
      : []),
  ];
  const buckets = await db.authRateLimitBucket.findMany({
    where: {
      OR: subjects,
      blockedUntil: { gt: now },
    },
    select: { id: true },
    take: 1,
  });
  return buckets.length > 0;
}

export async function recordLoginFailure(input: {
  prisma: PrismaClient;
  identifierHash: string;
  networkHash: string | null;
  identifierKind: "username" | "email" | "invalid";
  now: Date;
  correlationId: string;
}): Promise<void> {
  await retrySerializableTransaction(() =>
    input.prisma.$transaction(
      async (transaction) => {
        await lockRateLimitSubjects(
          transaction,
          input.identifierHash,
          input.networkHash,
        );
        if (
          await isLoginRateLimited(
            transaction,
            input.identifierHash,
            input.networkHash,
            input.now,
          )
        ) {
          return;
        }
        await recordFailureInTransaction(transaction, input);
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
    ),
  );
}

export async function admitLoginAttempt(input: {
  prisma: PrismaClient;
  candidate: LoginCandidate | null;
  credentialsValid: boolean;
  identifierKind: "username" | "email" | "invalid";
  sessionBinding: string;
  sessionDigestKey: Uint8Array;
  networkHash: string | null;
  userAgentSummary: string | null;
  identifierHash: string;
  now: Date;
  correlationId: string;
}): Promise<{
  sessionId: string;
  absoluteExpiresAt: Date;
  authzVersion: number;
  displayName: string;
} | null> {
  return input.prisma.$transaction(
    async (transaction) => {
      await lockRateLimitSubjects(
        transaction,
        input.identifierHash,
        input.networkHash,
      );
      const rateLimited = await isLoginRateLimited(
        transaction,
        input.identifierHash,
        input.networkHash,
        input.now,
      );
      if (rateLimited) return null;

      if (!input.credentialsValid || !input.candidate) {
        await recordFailureInTransaction(transaction, input);
        return null;
      }

      await transaction.$queryRaw`
        SELECT id FROM users WHERE id = ${input.candidate.id}::uuid FOR UPDATE
      `;
      const current = await transaction.user.findUniqueOrThrow({
        where: { id: input.candidate.id },
        select: {
          displayName: true,
          passwordHash: true,
          status: true,
          authzVersion: true,
        },
      });
      if (
        current.status !== "ACTIVE" ||
        !current.passwordHash ||
        current.passwordHash !== input.candidate.passwordHash
      ) {
        await recordFailureInTransaction(transaction, input);
        return null;
      }

      const sessionId = randomUUID();
      const { idleExpiresAt, absoluteExpiresAt } = sessionExpiryFrom(input.now);
      await transaction.session.create({
        data: {
          id: sessionId,
          userId: input.candidate.id,
          tokenHash: digestSecret(
            "session",
            input.sessionBinding,
            input.sessionDigestKey,
          ),
          authzVersion: current.authzVersion,
          createdAt: input.now,
          lastSeenAt: input.now,
          idleExpiresAt,
          absoluteExpiresAt,
          ipHash: input.networkHash,
          userAgentSummary: input.userAgentSummary,
        },
      });
      await transaction.user.update({
        where: { id: input.candidate.id },
        data: { lastLoginAt: input.now },
      });
      await transaction.authRateLimitBucket.deleteMany({
        where: {
          scope: "LOGIN_IDENTIFIER",
          subjectHash: input.identifierHash,
        },
      });
      await transaction.auditEvent.create({
        data: {
          actorUserId: input.candidate.id,
          eventType: "identity.login_succeeded",
          targetType: "user",
          targetId: input.candidate.id,
          outcome: "SUCCESS",
          correlationId: input.correlationId,
          metadata: { method: "credentials" },
        },
      });

      return {
        sessionId,
        absoluteExpiresAt,
        authzVersion: current.authzVersion,
        displayName: current.displayName,
      };
    },
    { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
  );
}

async function recordFailureInTransaction(
  transaction: Prisma.TransactionClient,
  input: {
    identifierHash: string;
    networkHash: string | null;
    identifierKind: "username" | "email" | "invalid";
    now: Date;
    correlationId: string;
  },
): Promise<void> {
  await incrementBucket(
    transaction,
    "LOGIN_IDENTIFIER",
    input.identifierHash,
    IDENTIFIER_FAILURE_LIMIT,
    input.now,
  );
  if (input.networkHash) {
    await incrementBucket(
      transaction,
      "LOGIN_NETWORK",
      input.networkHash,
      NETWORK_FAILURE_LIMIT,
      input.now,
    );
  }
  await transaction.auditEvent.create({
    data: {
      eventType: "identity.login_denied",
      outcome: "DENIED",
      correlationId: input.correlationId,
      ipHash: input.networkHash,
      metadata: {
        reason: "INVALID_CREDENTIALS",
        identifierKind: input.identifierKind,
      },
    },
  });
}

async function lockRateLimitSubjects(
  transaction: Prisma.TransactionClient,
  identifierHash: string,
  networkHash: string | null,
): Promise<void> {
  const lockKeys = [
    `LOGIN_IDENTIFIER:${identifierHash}`,
    ...(networkHash ? [`LOGIN_NETWORK:${networkHash}`] : []),
  ].sort();
  for (const lockKey of lockKeys) {
    await transaction.$queryRaw`
      SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))::text
    `;
  }
}

async function incrementBucket(
  transaction: Prisma.TransactionClient,
  scope: RateScope,
  subjectHash: string,
  limit: number,
  now: Date,
): Promise<void> {
  const windowStart = rateLimitWindowStart(now);
  const blockedUntil = new Date(
    windowStart.getTime() + RATE_LIMIT_WINDOW_MINUTES * 60 * 1000,
  );
  await transaction.$executeRaw`
    INSERT INTO auth_rate_limit_buckets
      (id, scope, subject_hash, window_start, attempts, blocked_until, updated_at)
    VALUES
      (${randomUUID()}::uuid, ${scope}::"RateLimitScope", ${subjectHash},
       ${windowStart}, 1, ${limit === 1 ? blockedUntil : null}, ${now})
    ON CONFLICT (scope, subject_hash, window_start)
    DO UPDATE SET
      attempts = auth_rate_limit_buckets.attempts + 1,
      blocked_until = CASE
        WHEN auth_rate_limit_buckets.attempts + 1 >= ${limit}
        THEN ${blockedUntil}
        ELSE auth_rate_limit_buckets.blocked_until
      END,
      updated_at = ${now}
  `;
}
