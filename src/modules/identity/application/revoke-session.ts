import { randomUUID } from "node:crypto";

import { Prisma, type PrismaClient } from "@prisma/client";

import { retrySerializableTransaction } from "../infrastructure/serializable-retry";
import { sessionDigestKey } from "../security/auth-secrets";
import { digestSecret } from "../security/secret-digest";
import type { AuthClaims } from "../server/auth-claims";

export async function revokeSessionForLogout(input: {
  prisma: PrismaClient;
  claims: AuthClaims;
  now?: Date;
}): Promise<void> {
  const now = input.now ?? new Date();
  const tokenHash = digestSecret(
    "session",
    input.claims.sessionBinding,
    sessionDigestKey(),
  );
  await retrySerializableTransaction(() =>
    input.prisma.$transaction(
      async (transaction) => {
        await transaction.$queryRaw`
        SELECT id FROM sessions WHERE id = ${input.claims.sessionId}::uuid FOR UPDATE
      `;
        const session = await transaction.session.findFirst({
          where: {
            id: input.claims.sessionId,
            userId: input.claims.sub,
            tokenHash,
          },
        });
        if (!session) throw new Error("Invalid session.");
        if (!session.revokedAt) {
          await transaction.session.update({
            where: { id: session.id },
            data: { revokedAt: now, revokeReason: "LOGOUT" },
          });
          await transaction.auditEvent.create({
            data: {
              actorUserId: input.claims.sub,
              eventType: "identity.logout",
              targetType: "session",
              targetId: session.id,
              outcome: "SUCCESS",
              correlationId: randomUUID(),
              metadata: { reason: "staff_logout" },
            },
          });
        }
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    ),
  );
}
