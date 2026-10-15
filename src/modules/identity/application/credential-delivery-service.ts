import { randomUUID } from "node:crypto";

import { type Prisma, type PrismaClient } from "@prisma/client";

import { decryptOutboxPayload } from "../security/credential-secret";
import type {
  CredentialEmailMessage,
  CredentialEmailProvider,
  CredentialEmailResult,
} from "./credential-email-provider";

const MAX_DELIVERY_ATTEMPTS = 3;
const CLAIM_LIFETIME_MS = 2 * 60_000;
const CLEANUP_BATCH_LIMIT = 100;

const PRE_PROVIDER_FAILURE = {
  decryption: "PAYLOAD_DECRYPTION_FAILED",
  malformed: "MALFORMED_PAYLOAD",
  origin: "INVALID_PUBLIC_ORIGIN",
} as const;

type DeliveryOutcome =
  | "ACCEPTED"
  | "FAILED"
  | "RETRY_QUEUED"
  | "UNKNOWN"
  | "CANCELLED";

type ClaimedDelivery = {
  id: string;
  claimToken: string;
  attemptNumber: number;
  encryptedPayload: string;
  grantExpiresAt: Date;
  userId: string;
};

export async function deliverQueuedCredentialEmail(input: {
  prisma: PrismaClient;
  provider: CredentialEmailProvider;
  deliveryId: string;
  publicOrigin: string;
  now?: Date;
}): Promise<DeliveryOutcome> {
  const now = input.now ?? new Date();
  const claimed = await claimDelivery(input.prisma, input.deliveryId, now);
  if (claimed === "UNKNOWN") return "UNKNOWN";
  if (!claimed) return "CANCELLED";

  let decrypted: unknown;
  try {
    decrypted = decryptOutboxPayload(claimed.encryptedPayload);
  } catch {
    await finalizePreProviderFailure(
      input.prisma,
      claimed,
      PRE_PROVIDER_FAILURE.decryption,
      now,
    );
    return "FAILED";
  }
  if (!isCredentialPayload(decrypted)) {
    await finalizePreProviderFailure(
      input.prisma,
      claimed,
      PRE_PROVIDER_FAILURE.malformed,
      now,
    );
    return "FAILED";
  }
  let publicOrigin: string;
  try {
    const url = new URL(input.publicOrigin);
    const loopback = ["127.0.0.1", "::1", "localhost"].includes(url.hostname);
    if (
      (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
      url.username ||
      url.password ||
      url.origin === "null"
    )
      throw new Error("Unsafe public origin.");
    publicOrigin = url.origin;
  } catch {
    await finalizePreProviderFailure(
      input.prisma,
      claimed,
      PRE_PROVIDER_FAILURE.origin,
      now,
    );
    return "FAILED";
  }
  const message: CredentialEmailMessage = {
    idempotencyKey: claimed.id,
    recipient: decrypted.recipient,
    setupFragmentUrl: `${publicOrigin}/credentials/setup#token=${decrypted.credential}`,
    expiresAt: claimed.grantExpiresAt,
    purpose: decrypted.purpose,
  };

  let result: CredentialEmailResult;
  try {
    // This external call is deliberately outside a database transaction. The
    // stable delivery id lets a compliant provider deduplicate a stale claim.
    result = await input.provider.send(message);
  } catch {
    await finalizeAmbiguous(input.prisma, claimed, now);
    return "UNKNOWN";
  }

  return finalizeClaim(input.prisma, claimed, result, now);
}

async function claimDelivery(
  prisma: PrismaClient,
  deliveryId: string,
  now: Date,
): Promise<ClaimedDelivery | "UNKNOWN" | null> {
  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM credential_grant_deliveries WHERE id = ${deliveryId}::uuid FOR UPDATE`;
    const delivery = await tx.credentialGrantDelivery.findUnique({
      where: { id: deliveryId },
      include: { grant: true },
    });
    const expiredClaim =
      delivery?.status === "CLAIMED" &&
      delivery.claimExpiresAt !== null &&
      delivery.claimExpiresAt <= now;
    if (delivery && expiredClaim) {
      const claimed = claimedDeliveryFrom(delivery);
      await tx.credentialGrantDelivery.update({
        where: { id: delivery.id },
        data: {
          status: "UNKNOWN",
          failureCode: "EXPIRED_CLAIM_OUTCOME_UNKNOWN",
          claimToken: null,
          claimExpiresAt: null,
        },
      });
      await recordDeliveryAudit(
        tx,
        claimed,
        false,
        "EXPIRED_CLAIM_OUTCOME_UNKNOWN",
      );
      return "UNKNOWN";
    }
    if (
      !delivery ||
      delivery.channel !== "EMAIL" ||
      delivery.status !== "QUEUED" ||
      !delivery.encryptedPayload ||
      !delivery.payloadExpiresAt ||
      delivery.attemptCount >= MAX_DELIVERY_ATTEMPTS ||
      delivery.payloadExpiresAt <= now ||
      delivery.grant.expiresAt <= now ||
      delivery.grant.revokedAt ||
      delivery.grant.consumedAt
    ) {
      if (
        delivery?.status === "UNKNOWN" &&
        delivery.encryptedPayload &&
        delivery.payloadExpiresAt &&
        delivery.payloadExpiresAt <= now
      ) {
        await tx.credentialGrantDelivery.update({
          where: { id: delivery.id },
          data: { encryptedPayload: null, payloadExpiresAt: null },
        });
        return null;
      }
      if (
        delivery?.encryptedPayload &&
        delivery.status !== "CLAIMED" &&
        delivery.status !== "UNKNOWN"
      ) {
        await tx.credentialGrantDelivery.update({
          where: { id: delivery.id },
          data: {
            status: "CANCELLED",
            encryptedPayload: null,
            payloadExpiresAt: null,
            claimToken: null,
            claimExpiresAt: null,
          },
        });
      }
      return null;
    }

    const claimToken = randomUUID();
    const claimed = await tx.credentialGrantDelivery.update({
      where: { id: delivery.id },
      data: {
        status: "CLAIMED",
        claimToken,
        claimExpiresAt: new Date(now.getTime() + CLAIM_LIFETIME_MS),
        lastAttemptAt: now,
        attemptCount: { increment: 1 },
      },
    });
    return {
      id: delivery.id,
      claimToken,
      attemptNumber: claimed.attemptCount,
      encryptedPayload: delivery.encryptedPayload,
      grantExpiresAt: delivery.grant.expiresAt,
      userId: delivery.userId,
    };
  });
}

/**
 * Removes expired ciphertext in bounded batches. UNKNOWN rows deliberately
 * require an approved reconciliation decision before expiry; after expiry the
 * credential can no longer be delivered and ciphertext is always destroyed.
 */
export async function cleanupExpiredCredentialDeliveryPayloads(input: {
  prisma: PrismaClient;
  now?: Date;
  limit?: number;
}): Promise<number> {
  const now = input.now ?? new Date();
  const limit = Math.min(Math.max(input.limit ?? CLEANUP_BATCH_LIMIT, 1), 500);
  const candidates = await input.prisma.credentialGrantDelivery.findMany({
    where: { encryptedPayload: { not: null }, payloadExpiresAt: { lte: now } },
    orderBy: { payloadExpiresAt: "asc" },
    take: limit,
    select: { id: true },
  });
  let cleaned = 0;
  for (const candidate of candidates) {
    cleaned += await input.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM credential_grant_deliveries WHERE id = ${candidate.id}::uuid FOR UPDATE`;
      const delivery = await tx.credentialGrantDelivery.findUnique({
        where: { id: candidate.id },
        include: { grant: true },
      });
      if (
        !delivery?.encryptedPayload ||
        !delivery.payloadExpiresAt ||
        delivery.payloadExpiresAt > now
      )
        return 0;
      if (delivery.status === "CLAIMED") {
        const claimed = claimedDeliveryFrom(delivery);
        await tx.credentialGrantDelivery.update({
          where: { id: delivery.id },
          data: {
            status: "UNKNOWN",
            failureCode: "EXPIRED_CLAIM_OUTCOME_UNKNOWN",
            encryptedPayload: null,
            payloadExpiresAt: null,
            claimToken: null,
            claimExpiresAt: null,
          },
        });
        await recordDeliveryAudit(
          tx,
          claimed,
          false,
          "EXPIRED_CLAIM_OUTCOME_UNKNOWN",
        );
      } else {
        await tx.credentialGrantDelivery.update({
          where: { id: delivery.id },
          data: {
            status:
              delivery.status === "QUEUED" ? "CANCELLED" : delivery.status,
            encryptedPayload: null,
            payloadExpiresAt: null,
            claimToken: null,
            claimExpiresAt: null,
          },
        });
      }
      return 1;
    });
  }
  return cleaned;
}

async function finalizeClaim(
  prisma: PrismaClient,
  claimed: ClaimedDelivery,
  result: CredentialEmailResult,
  now: Date,
): Promise<DeliveryOutcome> {
  return prisma.$transaction(async (tx) => {
    const retry =
      !result.accepted &&
      result.failureCode === "TEMPORARY" &&
      claimed.attemptNumber < MAX_DELIVERY_ATTEMPTS;
    const updated = await tx.credentialGrantDelivery.updateMany({
      where: {
        id: claimed.id,
        status: "CLAIMED",
        claimToken: claimed.claimToken,
      },
      data: result.accepted
        ? {
            status: "ACCEPTED",
            providerMessageId: result.messageId.slice(0, 200),
            deliveredAt: now,
            encryptedPayload: null,
            payloadExpiresAt: null,
            claimToken: null,
            claimExpiresAt: null,
          }
        : {
            status: retry ? "QUEUED" : "FAILED",
            failureCode: result.failureCode,
            encryptedPayload: retry ? undefined : null,
            payloadExpiresAt: retry ? undefined : null,
            claimToken: null,
            claimExpiresAt: null,
          },
    });
    if (updated.count !== 1) return "UNKNOWN";
    await recordDeliveryAudit(
      tx,
      claimed,
      result.accepted,
      result.accepted ? undefined : result.failureCode,
    );
    return result.accepted ? "ACCEPTED" : retry ? "RETRY_QUEUED" : "FAILED";
  });
}

async function finalizeAmbiguous(
  prisma: PrismaClient,
  claimed: ClaimedDelivery,
  now: Date,
) {
  await prisma.$transaction(async (tx) => {
    const updated = await tx.credentialGrantDelivery.updateMany({
      where: {
        id: claimed.id,
        status: "CLAIMED",
        claimToken: claimed.claimToken,
      },
      data: {
        status: "UNKNOWN",
        failureCode: "AMBIGUOUS_PROVIDER_OUTCOME",
        lastAttemptAt: now,
        claimToken: null,
        claimExpiresAt: null,
      },
    });
    if (updated.count === 1)
      await recordDeliveryAudit(
        tx,
        claimed,
        false,
        "AMBIGUOUS_PROVIDER_OUTCOME",
      );
  });
}

async function finalizePreProviderFailure(
  prisma: PrismaClient,
  claimed: ClaimedDelivery,
  failureCode: (typeof PRE_PROVIDER_FAILURE)[keyof typeof PRE_PROVIDER_FAILURE],
  now: Date,
) {
  await prisma.$transaction(async (tx) => {
    const updated = await tx.credentialGrantDelivery.updateMany({
      where: {
        id: claimed.id,
        status: "CLAIMED",
        claimToken: claimed.claimToken,
      },
      data: {
        status: "FAILED",
        failureCode,
        lastAttemptAt: now,
        encryptedPayload: null,
        payloadExpiresAt: null,
        claimToken: null,
        claimExpiresAt: null,
      },
    });
    if (updated.count === 1)
      await recordDeliveryAudit(tx, claimed, false, failureCode);
  });
}

function isCredentialPayload(value: unknown): value is {
  recipient: string;
  credential: string;
  purpose: CredentialEmailMessage["purpose"];
} {
  if (!value || typeof value !== "object") return false;
  const payload = value as Record<string, unknown>;
  return (
    typeof payload.recipient === "string" &&
    payload.recipient.length > 0 &&
    payload.recipient.length <= 320 &&
    typeof payload.credential === "string" &&
    payload.credential.length >= 40 &&
    payload.credential.length <= 96 &&
    (payload.purpose === "INITIAL_ENROLMENT" ||
      payload.purpose === "ADMINISTRATOR_RESET")
  );
}

function claimedDeliveryFrom(delivery: {
  id: string;
  claimToken: string | null;
  attemptCount: number;
  encryptedPayload: string | null;
  userId: string;
  grant: { expiresAt: Date };
}): ClaimedDelivery {
  if (!delivery.claimToken || !delivery.encryptedPayload)
    throw new Error("Claimed credential delivery is incomplete.");
  return {
    id: delivery.id,
    claimToken: delivery.claimToken,
    attemptNumber: delivery.attemptCount,
    encryptedPayload: delivery.encryptedPayload,
    grantExpiresAt: delivery.grant.expiresAt,
    userId: delivery.userId,
  };
}

async function recordDeliveryAudit(
  tx: Prisma.TransactionClient,
  claimed: ClaimedDelivery,
  accepted: boolean,
  failureCode?: string,
) {
  await tx.auditEvent.create({
    data: {
      eventType: accepted
        ? "identity.credential_email_accepted"
        : "identity.credential_email_failed",
      targetType: "user",
      targetId: claimed.userId,
      outcome: accepted ? "SUCCESS" : "FAILURE",
      correlationId: randomUUID(),
      metadata: failureCode ? { failureCode } : {},
    },
  });
}
