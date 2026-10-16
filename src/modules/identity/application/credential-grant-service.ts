import { randomUUID } from "node:crypto";

import { Prisma, type PrismaClient, type UserStatus } from "@prisma/client";

import {
  GENERIC_CREDENTIAL_FAILURE,
  grantExpiresAt,
  issueCredentialGrantSchema,
  redeemCredentialGrantSchema,
} from "../domain/credential-grant-policy";
import { retrySerializableTransaction } from "../infrastructure/serializable-retry";
import {
  credentialGrantDigestKey,
  rateLimitDigestKey,
} from "../security/auth-secrets";
import {
  encryptOutboxPayload,
  formatVoucher,
  generateCredential,
  normalizeVoucher,
} from "../security/credential-secret";
import { hashPassword } from "../security/password";
import {
  type HeaderSource,
  trustedNetworkIdentifier,
} from "../security/request-security";
import { digestSecret } from "../security/secret-digest";
import type { AuthClaims } from "../server/auth-claims";
import { withAuthorizedTransaction } from "../server/guards";

type Purpose = "INITIAL_ENROLMENT" | "ADMINISTRATOR_RESET";
type Channel = "EMAIL" | "IN_PERSON";

export class CredentialGrantError extends Error {}

export async function issueCredentialGrant(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
  command: unknown;
  now?: Date;
}) {
  const command = issueCredentialGrantSchema.parse(input.command);
  const now = input.now ?? new Date();
  const secret = generateCredential();
  const domain =
    command.purpose === "INITIAL_ENROLMENT"
      ? "credential-enrolment"
      : "credential-recovery";
  const tokenHash = digestSecret(domain, secret, credentialGrantDigestKey());
  return withAuthorizedTransaction({
    prisma: input.prisma,
    claims: input.claims,
    permission:
      command.purpose === "INITIAL_ENROLMENT"
        ? "users:issue_enrolment"
        : "users:reset_password",
    now,
    operation: async (tx, principal) => {
      await tx.$queryRaw`SELECT id FROM users WHERE id = ${command.userId}::uuid FOR UPDATE`;
      const target = await tx.user.findUnique({
        where: { id: command.userId },
        include: { roles: { include: { role: true } } },
      });
      if (!target) denied();
      const codes = target.roles
        .filter(({ role }) => role.isActive)
        .map(({ role }) => role.code);
      if (codes.includes("super_administrator")) denied();
      if (codes.includes("administrator")) {
        await assertCurrentSuperAdministrator(tx, principal.userId);
      }
      assertEligible(
        command.purpose,
        target.status,
        Boolean(target.passwordHash),
      );
      if (command.channel === "EMAIL") {
        if (!target.emailNormalized) denied();
        if (
          command.purpose === "ADMINISTRATOR_RESET" &&
          !target.emailVerifiedAt
        )
          denied();
      }
      await admitIssuance(
        tx,
        principal.userId,
        target.id,
        command.channel,
        now,
      );
      await tx.passwordResetGrant.updateMany({
        where: {
          userId: target.id,
          purpose: command.purpose,
          consumedAt: null,
          revokedAt: null,
        },
        data: { revokedAt: now },
      });
      const expiresAt = grantExpiresAt(now);
      const grant = await tx.passwordResetGrant.create({
        data: {
          userId: target.id,
          requestedById: principal.userId,
          tokenHash,
          purpose: command.purpose,
          deliveryChannel: command.channel,
          subjectEmailVersion:
            command.channel === "EMAIL" ? target.emailVersion : null,
          subjectPasswordVersion: target.passwordVersion,
          subjectStatus: target.status,
          issuedAt: now,
          createdAt: now,
          expiresAt,
        },
      });
      const destinationHash = target.emailNormalized
        ? digestSecret(
            "credential-destination",
            target.emailNormalized,
            credentialGrantDigestKey(),
          )
        : null;
      await tx.credentialGrantDelivery.create({
        data: {
          grantId: grant.id,
          userId: target.id,
          channel: command.channel,
          status: command.channel === "EMAIL" ? "QUEUED" : "DISPLAYED",
          destinationHash: command.channel === "EMAIL" ? destinationHash : null,
          encryptedPayload:
            command.channel === "EMAIL"
              ? encryptOutboxPayload({
                  recipient: target.emailNormalized,
                  credential: secret,
                  purpose: command.purpose,
                })
              : null,
          payloadExpiresAt: command.channel === "EMAIL" ? expiresAt : null,
        },
      });
      await tx.auditEvent.create({
        data: {
          actorUserId: principal.userId,
          eventType: "identity.credential_grant_issued",
          targetType: "user",
          targetId: target.id,
          outcome: "SUCCESS",
          correlationId: randomUUID(),
          metadata: {
            purpose: command.purpose,
            channel: command.channel,
            verificationMethod: command.verificationAttestation,
          },
        },
      });
      return {
        grantId: grant.id,
        expiresAt,
        voucher: command.channel === "IN_PERSON" ? formatVoucher(secret) : null,
      };
    },
  });
}

export async function redeemCredentialGrant(input: {
  prisma: PrismaClient;
  command: unknown;
  headers: HeaderSource;
  now?: Date;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  const parsed = redeemCredentialGrantSchema.safeParse(input.command);
  if (!parsed.success) return failure();
  const now = input.now ?? new Date();
  const credential = normalizeVoucher(parsed.data.credential);
  const enrolmentHash = digestSecret(
    "credential-enrolment",
    credential,
    credentialGrantDigestKey(),
  );
  const recoveryHash = digestSecret(
    "credential-recovery",
    credential,
    credentialGrantDigestKey(),
  );
  const grant = await input.prisma.passwordResetGrant.findFirst({
    where: { tokenHash: { in: [enrolmentHash, recoveryHash] } },
    select: { id: true },
  });
  // Arbitrary unknown inputs share one bounded bucket. Real grants retain a
  // per-token bucket, preventing attacker-controlled database cardinality
  // without changing valid-token admission or public failure behaviour.
  const tokenSubject = digestSecret(
    "rate-limit",
    grant ? credential : "unknown-credential",
    rateLimitDigestKey(),
  );
  const network = trustedNetworkIdentifier(input.headers);
  const networkSubject = network
    ? digestSecret("rate-limit", network, rateLimitDigestKey())
    : null;
  if (!(await admitRedemption(input.prisma, tokenSubject, networkSubject, now)))
    return failure();
  let passwordHash: string;
  try {
    passwordHash = await hashPassword(parsed.data.password);
  } catch {
    return failure();
  }
  if (!grant) return failure();
  try {
    await retrySerializableTransaction(() =>
      input.prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${grant.id}, 0))`;
          const current = await tx.passwordResetGrant.findUnique({
            where: { id: grant.id },
            include: {
              user: { include: { roles: { include: { role: true } } } },
              requestedBy: {
                include: {
                  roles: {
                    include: {
                      role: {
                        include: {
                          permissions: { include: { permission: true } },
                        },
                      },
                    },
                  },
                },
              },
            },
          });
          if (
            !current ||
            current.consumedAt ||
            current.revokedAt ||
            current.expiresAt <= now ||
            current.purpose === "PROTECTED_RECOVERY"
          )
            denied();
          const user = current.user;
          if (
            user.roles.some(
              ({ role }) =>
                role.isActive && role.code === "super_administrator",
            )
          )
            denied();
          if (user.passwordVersion !== current.subjectPasswordVersion) denied();
          if (
            current.deliveryChannel === "EMAIL" &&
            user.emailVersion !== current.subjectEmailVersion
          )
            denied();
          if (
            current.deliveryChannel === "EMAIL" &&
            current.purpose === "ADMINISTRATOR_RESET" &&
            (!user.emailNormalized || !user.emailVerifiedAt)
          )
            denied();
          if (!current.requestedBy || current.requestedBy.status !== "ACTIVE")
            denied();
          const issuerPermissions = new Set(
            current.requestedBy.roles.flatMap(({ role }) =>
              role.isActive
                ? role.permissions.map(({ permission }) => permission.code)
                : [],
            ),
          );
          const targetIsAdmin = user.roles.some(
            ({ role }) => role.isActive && role.code === "administrator",
          );
          if (targetIsAdmin) {
            if (!issuerPermissions.has("users:recover_administrator")) denied();
            await assertCurrentSuperAdministrator(tx, current.requestedBy.id);
          } else if (
            !issuerPermissions.has(
              current.purpose === "INITIAL_ENROLMENT"
                ? "users:issue_enrolment"
                : "users:reset_password",
            )
          )
            denied();
          assertEligible(
            current.purpose as Purpose,
            user.status,
            Boolean(user.passwordHash),
          );
          const consumed = await tx.passwordResetGrant.updateMany({
            where: { id: current.id, consumedAt: null, revokedAt: null },
            data: { consumedAt: now },
          });
          if (consumed.count !== 1) denied();
          const nextStatus: UserStatus =
            current.purpose === "INITIAL_ENROLMENT" &&
            user.status === "PENDING_PASSWORD"
              ? "ACTIVE"
              : user.status;
          await tx.user.update({
            where: { id: user.id },
            data: {
              passwordHash,
              passwordChangedAt: now,
              passwordVersion: { increment: 1 },
              authzVersion: { increment: 1 },
              status: nextStatus,
              ...(current.deliveryChannel === "EMAIL" &&
              current.purpose === "INITIAL_ENROLMENT"
                ? { emailVerifiedAt: now }
                : {}),
            },
          });
          const revoked = await tx.session.updateMany({
            where: { userId: user.id, revokedAt: null },
            data: { revokedAt: now, revokeReason: "PASSWORD_CHANGED" },
          });
          await tx.passwordResetGrant.updateMany({
            where: {
              userId: user.id,
              id: { not: current.id },
              consumedAt: null,
              revokedAt: null,
            },
            data: { revokedAt: now },
          });
          await tx.credentialGrantDelivery.updateMany({
            where: { grantId: current.id },
            data: {
              status: "ACKNOWLEDGED",
              acknowledgedAt: now,
              encryptedPayload: null,
              payloadExpiresAt: null,
            },
          });
          await tx.auditEvent.create({
            data: {
              actorUserId: null,
              eventType: "identity.credential_redemption_succeeded",
              targetType: "user",
              targetId: user.id,
              outcome: "SUCCESS",
              correlationId: randomUUID(),
              metadata: {
                purpose: current.purpose,
                channel: current.deliveryChannel,
                revokedSessions: revoked.count,
              },
            },
          });
        },
        { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
      ),
    );
    return { ok: true };
  } catch {
    return failure();
  }
}

function assertEligible(
  purpose: Purpose,
  status: UserStatus,
  hasPassword: boolean,
) {
  if (purpose === "INITIAL_ENROLMENT") {
    if (status !== "PENDING_PASSWORD" || hasPassword) denied();
  } else if (status === "INACTIVE" || status === "PENDING_PASSWORD") denied();
}

async function assertCurrentSuperAdministrator(
  tx: Prisma.TransactionClient,
  userId: string,
) {
  const membership = await tx.userRole.findFirst({
    where: {
      userId,
      role: { code: "super_administrator", isProtected: true, isActive: true },
    },
  });
  if (!membership) denied();
}

async function admitIssuance(
  tx: Prisma.TransactionClient,
  actorId: string,
  userId: string,
  channel: Channel,
  now: Date,
) {
  const limits = [
    ["CREDENTIAL_ISSUE_ACTOR", actorId, 20, 15],
    ["CREDENTIAL_ISSUE_USER", userId, 3, 60],
    [
      channel === "EMAIL" ? "CREDENTIAL_EMAIL_USER" : "CREDENTIAL_VOUCHER_USER",
      userId,
      3,
      60,
    ],
  ] as const;
  for (const [scope, subject, limit, minutes] of limits) {
    if (!(await incrementBucket(tx, scope, subject, limit, minutes, now)))
      throw new CredentialGrantError("Rate limited.");
  }
}

async function admitRedemption(
  prisma: PrismaClient,
  token: string,
  network: string | null,
  now: Date,
) {
  try {
    return await prisma.$transaction(async (tx) => {
      const windowStart = redemptionWindowStart(now);
      await tx.authRateLimitBucket.deleteMany({
        where: {
          scope: {
            in: ["CREDENTIAL_CONSUME_TOKEN", "CREDENTIAL_CONSUME_NETWORK"],
          },
          windowStart: { lt: new Date(windowStart.getTime() - 15 * 60_000) },
        },
      });
      const tokenAllowed = await incrementBucket(
        tx,
        "CREDENTIAL_CONSUME_TOKEN",
        token,
        5,
        15,
        now,
      );
      const networkAllowed = network
        ? await incrementBucket(
            tx,
            "CREDENTIAL_CONSUME_NETWORK",
            network,
            30,
            15,
            now,
          )
        : true;
      return tokenAllowed && networkAllowed;
    });
  } catch {
    return false;
  }
}

async function incrementBucket(
  tx: Prisma.TransactionClient,
  scope: Parameters<typeof tx.authRateLimitBucket.upsert>[0]["create"]["scope"],
  subject: string,
  limit: number,
  minutes: number,
  now: Date,
) {
  const subjectHash = /^[0-9a-f]{64}$/.test(subject)
    ? subject
    : digestSecret("rate-limit", subject, rateLimitDigestKey());
  const windowMs = minutes * 60_000;
  const windowStart = new Date(Math.floor(now.getTime() / windowMs) * windowMs);
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${scope + subjectHash}, 0))`;
  const existing = await tx.authRateLimitBucket.findUnique({
    where: {
      scope_subjectHash_windowStart: { scope, subjectHash, windowStart },
    },
  });
  if (existing && existing.attempts >= limit) return false;
  const bucket = await tx.authRateLimitBucket.upsert({
    where: {
      scope_subjectHash_windowStart: { scope, subjectHash, windowStart },
    },
    create: { scope, subjectHash, windowStart, attempts: 1 },
    update: {
      attempts: { increment: 1 },
      blockedUntil:
        existing?.attempts === limit - 1
          ? new Date(windowStart.getTime() + windowMs)
          : undefined,
    },
  });
  return bucket.attempts <= limit;
}

function redemptionWindowStart(now: Date) {
  const windowMs = 15 * 60_000;
  return new Date(Math.floor(now.getTime() / windowMs) * windowMs);
}

function denied(): never {
  throw new CredentialGrantError(GENERIC_CREDENTIAL_FAILURE);
}
function failure() {
  return { ok: false as const, message: GENERIC_CREDENTIAL_FAILURE };
}
