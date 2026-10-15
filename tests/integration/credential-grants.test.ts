import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { authenticateCredentials } from "../../src/modules/identity/application/authenticate-credentials";
import {
  issueCredentialGrant,
  redeemCredentialGrant,
} from "../../src/modules/identity/application/credential-grant-service";
import {
  cleanupExpiredCredentialDeliveryPayloads,
  deliverQueuedCredentialEmail,
} from "../../src/modules/identity/application/credential-delivery-service";
import type { CredentialEmailProvider } from "../../src/modules/identity/application/credential-email-provider";
import { seedInitialIdentityCatalog } from "../../src/modules/identity/infrastructure/catalog-repository";
import {
  hashPassword,
  verifyPassword,
} from "../../src/modules/identity/security/password";
import {
  encryptOutboxPayload,
  formatVoucher,
  generateCredential,
  normalizeVoucher,
} from "../../src/modules/identity/security/credential-secret";
import { rateLimitDigestKey } from "../../src/modules/identity/security/auth-secrets";
import { digestSecret } from "../../src/modules/identity/security/secret-digest";

const runtimeUrl = process.env.TEST_DATABASE_URL;
const migrationUrl = process.env.TEST_MIGRATION_DATABASE_URL;
if (!runtimeUrl || !migrationUrl)
  throw new Error("Integration database URLs are required.");
const prisma = new PrismaClient({ datasourceUrl: runtimeUrl });
const migration = new PrismaClient({ datasourceUrl: migrationUrl });
const users: string[] = [];
let administrator: Awaited<ReturnType<typeof principal>>;

beforeAll(async () => {
  await Promise.all([prisma.$connect(), migration.$connect()]);
  await seedInitialIdentityCatalog(migration);
  administrator = await principal("administrator");
});

afterAll(async () => {
  if (users.length) {
    await migration.session.deleteMany({ where: { userId: { in: users } } });
    await migration.passwordResetGrant.updateMany({
      where: { userId: { in: users }, consumedAt: null, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    await migration.userRole.deleteMany({ where: { userId: { in: users } } });
    await migration.user.updateMany({
      where: { id: { in: users } },
      data: { status: "INACTIVE", passwordHash: null },
    });
  }
  await Promise.all([prisma.$disconnect(), migration.$disconnect()]);
});

describe("B4 credential grants", () => {
  it("rejects missing and tampered server-side identity attestations", async () => {
    const target = await pendingUser(false);
    const base = command(target.id, "INITIAL_ENROLMENT", "IN_PERSON");
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: { ...base, verificationAttestation: undefined },
      }),
    ).rejects.toThrow();
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: { ...base, verificationAttestation: "CLIENT_SAYS_YES" },
      }),
    ).rejects.toThrow();
    expect(
      await prisma.passwordResetGrant.count({ where: { userId: target.id } }),
    ).toBe(0);
  });

  it("atomically enrolls pending staff, activates them, and leaves email unverified after handover", async () => {
    const target = await pendingUser(true);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "IN_PERSON"),
    });
    expect(issued.voucher).toBeTruthy();
    const password = `enrolled password ${randomUUID()}`;
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential: issued.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual({ ok: true });
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: target.id },
    });
    expect(user).toMatchObject({
      status: "ACTIVE",
      passwordVersion: 1,
      emailVerifiedAt: null,
    });
    expect(await verifyPassword(user.passwordHash!, password)).toBe(true);
  });

  it("allows exactly one concurrent redemption and rejects replay", async () => {
    const target = await pendingUser(false);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "IN_PERSON"),
    });
    const password = `concurrent password ${randomUUID()}`;
    const results = await Promise.all(
      [1, 2].map(() =>
        redeemCredentialGrant({
          prisma,
          headers: new Headers(),
          command: {
            credential: issued.voucher,
            password,
            passwordConfirmation: password,
          },
        }),
      ),
    );
    expect(results.filter(({ ok }) => ok)).toHaveLength(1);
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential: issued.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toMatchObject({ ok: false });
  });

  it("requires verified email for recovery and never permits inactive recovery", async () => {
    const active = await activeUser("cashier", true);
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: command(active.id, "ADMINISTRATOR_RESET", "EMAIL"),
      }),
    ).rejects.toThrow();
    await migration.user.update({
      where: { id: active.id },
      data: { emailVerifiedAt: new Date() },
    });
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: command(active.id, "ADMINISTRATOR_RESET", "EMAIL"),
      }),
    ).resolves.toMatchObject({ voucher: null });
    await migration.user.update({
      where: { id: active.id },
      data: { status: "INACTIVE" },
    });
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: command(active.id, "ADMINISTRATOR_RESET", "IN_PERSON"),
      }),
    ).rejects.toThrow();
  });

  it("prevents an ordinary Administrator recovering another Administrator", async () => {
    const target = await activeUser("administrator", false);
    await expect(
      issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: command(target.id, "ADMINISTRATOR_RESET", "IN_PERSON"),
      }),
    ).rejects.toThrow();
  });

  it("durably counts the exact redemption threshold and repeated blocked attempts", async () => {
    const target = await pendingUser(false);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "IN_PERSON"),
    });
    const now = new Date();
    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(
        redeemCredentialGrant({
          prisma,
          headers: new Headers(),
          now,
          command: {
            credential: issued.voucher,
            password: "short",
            passwordConfirmation: "short",
          },
        }),
      ).resolves.toMatchObject({ ok: false });
    }
    const password = `threshold success ${randomUUID()}`;
    // The fifth attempt is admitted.
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        now,
        command: {
          credential: issued.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual({ ok: true });
    // The sixth and later attempts are blocked without counter amplification.
    for (let attempt = 0; attempt < 3; attempt += 1)
      await expect(
        redeemCredentialGrant({
          prisma,
          headers: new Headers(),
          now,
          command: {
            credential: issued.voucher,
            password,
            passwordConfirmation: password,
          },
        }),
      ).resolves.toMatchObject({ ok: false });
    expect(await tokenAttempts(issued.voucher!, now)).toBe(5);
  });

  it("purges credential-consumption buckets older than two windows", async () => {
    const now = new Date();
    const oldWindow = new Date(
      Math.floor(now.getTime() / (15 * 60_000)) * 15 * 60_000 - 16 * 60_000,
    );
    await migration.authRateLimitBucket.create({
      data: {
        scope: "CREDENTIAL_CONSUME_TOKEN",
        subjectHash: "a".repeat(64),
        windowStart: oldWindow,
        attempts: 5,
      },
    });
    const password = `retention check ${randomUUID()}`;
    await redeemCredentialGrant({
      prisma,
      headers: new Headers(),
      now,
      command: {
        credential: formatVoucher(generateCredential()),
        password,
        passwordConfirmation: password,
      },
    });
    expect(
      await prisma.authRateLimitBucket.count({
        where: {
          scope: "CREDENTIAL_CONSUME_TOKEN",
          subjectHash: "a".repeat(64),
          windowStart: oldWindow,
        },
      }),
    ).toBe(0);
  });

  it("durably serializes concurrent unknown and expired token attempts", async () => {
    const unknown = formatVoucher(generateCredential());
    const now = new Date();
    const password = `unknown token ${randomUUID()}`;
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        redeemCredentialGrant({
          prisma,
          headers: new Headers(),
          now,
          command: {
            credential: unknown,
            password,
            passwordConfirmation: password,
          },
        }),
      ),
    );
    expect(results).toEqual(
      Array.from({ length: 10 }, () => ({
        ok: false,
        message:
          "This setup credential is invalid, expired, or has already been used.",
      })),
    );
    expect(await tokenAttempts(unknown, now, false)).toBe(5);
    const unknownSubjectHash = digestSecret(
      "rate-limit",
      "unknown-credential",
      rateLimitDigestKey(),
    );
    expect(
      await prisma.authRateLimitBucket.count({
        where: {
          scope: "CREDENTIAL_CONSUME_TOKEN",
          subjectHash: unknownSubjectHash,
          windowStart: redemptionWindowStart(now),
        },
      }),
    ).toBe(1);

    const target = await pendingUser(false);
    const expired = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      now,
      command: command(target.id, "INITIAL_ENROLMENT", "IN_PERSON"),
    });
    const expiredNow = new Date(now.getTime() + 16 * 60_000);
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        now: expiredNow,
        command: {
          credential: expired.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual(results[0]);
    expect(await tokenAttempts(expired.voucher!, expiredNow)).toBe(1);
  });

  it("rechecks email version, account state, and issuer authority at redemption", async () => {
    const target = await activeUser("cashier", true);
    await migration.user.update({
      where: { id: target.id },
      data: { emailVerifiedAt: new Date() },
    });
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "ADMINISTRATOR_RESET", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    const provider = new CapturingProvider();
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("ACCEPTED");
    expect(provider.messages[0]?.idempotencyKey).toBe(delivery.id);
    expect(provider.observedDeliveryStatus).toBe("CLAIMED");
    const credential =
      provider.messages[0]!.setupFragmentUrl.split("#token=")[1];
    const changedEmail = `changed.${randomUUID()}@example.test`;
    await migration.user.update({
      where: { id: target.id },
      data: { email: changedEmail, emailNormalized: changedEmail },
    });
    const password = `email changed ${randomUUID()}`;
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toMatchObject({ ok: false });
  });

  it.each([
    ["verification cleared", { emailVerifiedAt: null }],
    ["email replaced", "REPLACE_EMAIL"],
    [
      "email removed",
      {
        email: null,
        emailNormalized: null,
        emailVersion: { increment: 1 },
        emailVerifiedAt: null,
      },
    ],
  ])(
    "rejects email recovery when the bound email has %s",
    async (_description, mutation) => {
      const { target, credential } = await issuedEmailRecovery();
      const replacementEmail = `replacement.${randomUUID()}@example.test`;
      await migration.user.update({
        where: { id: target.id },
        data:
          mutation === "REPLACE_EMAIL"
            ? {
                email: replacementEmail,
                emailNormalized: replacementEmail,
                emailVersion: { increment: 1 },
                emailVerifiedAt: new Date(),
              }
            : mutation,
      });
      const password = `email recheck ${randomUUID()}`;
      await expect(
        redeemCredentialGrant({
          prisma,
          headers: new Headers(),
          command: {
            credential,
            password,
            passwordConfirmation: password,
          },
        }),
      ).resolves.toMatchObject({ ok: false });
    },
  );

  it("redeems email recovery only while the bound email remains verified", async () => {
    const { credential } = await issuedEmailRecovery();
    const password = `verified recovery ${randomUUID()}`;
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual({ ok: true });
  });

  it("marks ambiguous provider outcomes without automatic redispatch", async () => {
    const target = await pendingUser(true);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    const provider: CredentialEmailProvider = {
      send: async () => {
        throw new Error("provider timeout after submission");
      },
    };
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("UNKNOWN");
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("CANCELLED");
    expect(
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: delivery.id },
      }),
    ).toMatchObject({
      status: "UNKNOWN",
      attemptCount: 1,
      failureCode: "AMBIGUOUS_PROVIDER_OUTCOME",
    });
  });

  it("marks expired claims unknown without redispatch and cleans expired ciphertext", async () => {
    const target = await pendingUser(true);
    const started = deferred<void>();
    const delayed = deferred<void>();
    let sends = 0;
    const issuedAt = new Date();
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      now: issuedAt,
      command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    const provider: CredentialEmailProvider = {
      send: async () => {
        sends += 1;
        started.resolve();
        await delayed.promise;
        return { accepted: true, messageId: "delayed-provider-result" };
      },
    };
    const first = deliverQueuedCredentialEmail({
      prisma,
      provider,
      deliveryId: delivery.id,
      publicOrigin: "http://127.0.0.1:3000",
      now: issuedAt,
    });
    await started.promise;
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
        now: new Date(issuedAt.getTime() + 3 * 60_000),
      }),
    ).resolves.toBe("UNKNOWN");
    delayed.resolve();
    await expect(first).resolves.toBe("UNKNOWN");
    expect(sends).toBe(1);
    expect(
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: delivery.id },
      }),
    ).toMatchObject({
      status: "UNKNOWN",
      failureCode: "EXPIRED_CLAIM_OUTCOME_UNKNOWN",
      encryptedPayload: expect.any(String),
    });
    await expect(
      cleanupExpiredCredentialDeliveryPayloads({
        prisma,
        now: new Date(issuedAt.getTime() + 16 * 60_000),
      }),
    ).resolves.toBeGreaterThanOrEqual(1);
    expect(
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: delivery.id },
      }),
    ).toMatchObject({
      status: "UNKNOWN",
      encryptedPayload: null,
      payloadExpiresAt: null,
    });
  });

  it("allows only one concurrent worker to dispatch a delivery claim", async () => {
    const target = await pendingUser(true);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    let sends = 0;
    const release = deferred<void>();
    const provider: CredentialEmailProvider = {
      send: async () => {
        sends += 1;
        await release.promise;
        return { accepted: true, messageId: "single-dispatch" };
      },
    };
    const first = deliverQueuedCredentialEmail({
      prisma,
      provider,
      deliveryId: delivery.id,
      publicOrigin: "http://127.0.0.1:3000",
    });
    while (sends === 0) await new Promise((resolve) => setTimeout(resolve, 1));
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("CANCELLED");
    release.resolve();
    await expect(first).resolves.toBe("ACCEPTED");
    expect(sends).toBe(1);
  });

  it.each([
    ["corrupted ciphertext", "corrupt", "PAYLOAD_DECRYPTION_FAILED"],
    [
      "malformed payload",
      encryptOutboxPayload({ unexpected: "shape" }),
      "MALFORMED_PAYLOAD",
    ],
  ])(
    "terminally fails %s before provider invocation",
    async (_label, payload, code) => {
      const target = await pendingUser(true);
      const issued = await issueCredentialGrant({
        prisma,
        claims: administrator.claims,
        command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
      });
      const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
        where: { grantId: issued.grantId },
      });
      await migration.credentialGrantDelivery.update({
        where: { id: delivery.id },
        data: { encryptedPayload: payload },
      });
      const provider = new CapturingProvider();
      await expect(
        deliverQueuedCredentialEmail({
          prisma,
          provider,
          deliveryId: delivery.id,
          publicOrigin: "http://127.0.0.1:3000",
        }),
      ).resolves.toBe("FAILED");
      expect(provider.messages).toHaveLength(0);
      expect(
        await prisma.credentialGrantDelivery.findUniqueOrThrow({
          where: { id: delivery.id },
        }),
      ).toMatchObject({
        status: "FAILED",
        failureCode: code,
        encryptedPayload: null,
        payloadExpiresAt: null,
      });
    },
  );

  it("terminally fails invalid public origin without exposing or sending the credential", async () => {
    const target = await pendingUser(true);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    const provider = new CapturingProvider();
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "not a valid origin",
      }),
    ).resolves.toBe("FAILED");
    expect(provider.messages).toHaveLength(0);
    expect(
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: delivery.id },
      }),
    ).toMatchObject({
      status: "FAILED",
      failureCode: "INVALID_PUBLIC_ORIGIN",
      encryptedPayload: null,
    });
  });

  it("retries bounded temporary delivery failures with one idempotency key", async () => {
    const target = await pendingUser(true);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "INITIAL_ENROLMENT", "EMAIL"),
    });
    const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
      where: { grantId: issued.grantId },
    });
    const keys: string[] = [];
    const provider: CredentialEmailProvider = {
      send: async (message) => {
        keys.push(message.idempotencyKey);
        return keys.length === 1
          ? { accepted: false, failureCode: "TEMPORARY" }
          : { accepted: true, messageId: "provider-stable-message" };
      },
    };
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("RETRY_QUEUED");
    await expect(
      deliverQueuedCredentialEmail({
        prisma,
        provider,
        deliveryId: delivery.id,
        publicOrigin: "http://127.0.0.1:3000",
      }),
    ).resolves.toBe("ACCEPTED");
    expect(keys).toEqual([delivery.id, delivery.id]);
    expect(
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: delivery.id },
      }),
    ).toMatchObject({
      status: "ACCEPTED",
      attemptCount: 2,
      encryptedPayload: null,
    });
  });

  it("preserves a locked account while changing its password", async () => {
    const target = await activeUser("cashier", false);
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "ADMINISTRATOR_RESET", "IN_PERSON"),
    });
    await migration.user.update({
      where: { id: target.id },
      data: { status: "LOCKED" },
    });
    const password = `locked recovery ${randomUUID()}`;
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential: issued.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual({ ok: true });
    expect(
      await prisma.user.findUniqueOrThrow({ where: { id: target.id } }),
    ).toMatchObject({ status: "LOCKED" });
  });

  it("rechecks issuer authority and atomically revokes sessions", async () => {
    const target = await activeUser("cashier", false);
    const oldPassword = `known old password ${randomUUID()}`;
    await migration.user.update({
      where: { id: target.id },
      data: {
        passwordHash: await hashPassword(oldPassword),
        passwordVersion: { increment: 1 },
      },
    });
    const targetClaims = await authenticateCredentials({
      prisma,
      identifier: target.username,
      password: oldPassword,
      headers: new Headers({ "user-agent": "b4-session-revocation" }),
    });
    if (!targetClaims) throw new Error("Target fixture authentication failed.");
    const issued = await issueCredentialGrant({
      prisma,
      claims: administrator.claims,
      command: command(target.id, "ADMINISTRATOR_RESET", "IN_PERSON"),
    });
    const password = `known new password ${randomUUID()}`;
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential: issued.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toEqual({ ok: true });
    expect(
      await prisma.session.findUniqueOrThrow({
        where: { id: targetClaims.sessionId },
      }),
    ).toMatchObject({ revokeReason: "PASSWORD_CHANGED" });
    expect(
      await prisma.auditEvent.count({
        where: {
          eventType: "identity.credential_redemption_succeeded",
          targetId: target.id,
          outcome: "SUCCESS",
        },
      }),
    ).toBe(1);

    const secondIssuer = await principal("administrator");
    const secondTarget = await activeUser("cashier", false);
    const secondGrant = await issueCredentialGrant({
      prisma,
      claims: secondIssuer.claims,
      command: command(secondTarget.id, "ADMINISTRATOR_RESET", "IN_PERSON"),
    });
    await migration.user.update({
      where: { id: secondIssuer.userId },
      data: { status: "INACTIVE" },
    });
    await expect(
      redeemCredentialGrant({
        prisma,
        headers: new Headers(),
        command: {
          credential: secondGrant.voucher,
          password,
          passwordConfirmation: password,
        },
      }),
    ).resolves.toMatchObject({ ok: false });
  });
});

async function issuedEmailRecovery() {
  const target = await activeUser("cashier", true);
  await migration.user.update({
    where: { id: target.id },
    data: { emailVerifiedAt: new Date() },
  });
  const issued = await issueCredentialGrant({
    prisma,
    claims: administrator.claims,
    command: command(target.id, "ADMINISTRATOR_RESET", "EMAIL"),
  });
  const delivery = await prisma.credentialGrantDelivery.findFirstOrThrow({
    where: { grantId: issued.grantId },
  });
  const provider = new CapturingProvider();
  await deliverQueuedCredentialEmail({
    prisma,
    provider,
    deliveryId: delivery.id,
    publicOrigin: "http://127.0.0.1:3000",
  });
  return {
    target,
    credential: provider.messages[0]!.setupFragmentUrl.split("#token=")[1]!,
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function command(
  userId: string,
  purpose: "INITIAL_ENROLMENT" | "ADMINISTRATOR_RESET",
  channel: "EMAIL" | "IN_PERSON",
) {
  return {
    userId,
    purpose,
    channel,
    verificationAttestation: "STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED",
  };
}

async function tokenAttempts(voucher: string, now: Date, known = true) {
  const subjectHash = digestSecret(
    "rate-limit",
    known ? normalizeVoucher(voucher) : "unknown-credential",
    rateLimitDigestKey(),
  );
  const windowStart = redemptionWindowStart(now);
  return (
    await prisma.authRateLimitBucket.findUniqueOrThrow({
      where: {
        scope_subjectHash_windowStart: {
          scope: "CREDENTIAL_CONSUME_TOKEN",
          subjectHash,
          windowStart,
        },
      },
    })
  ).attempts;
}

function redemptionWindowStart(now: Date) {
  return new Date(Math.floor(now.getTime() / (15 * 60_000)) * 15 * 60_000);
}

class CapturingProvider implements CredentialEmailProvider {
  readonly messages: Parameters<CredentialEmailProvider["send"]>[0][] = [];
  observedDeliveryStatus: string | null = null;

  async send(message: Parameters<CredentialEmailProvider["send"]>[0]) {
    this.messages.push(message);
    this.observedDeliveryStatus = (
      await prisma.credentialGrantDelivery.findUniqueOrThrow({
        where: { id: message.idempotencyKey },
      })
    ).status;
    return {
      accepted: true as const,
      messageId: `fake-${message.idempotencyKey}`,
    };
  }
}

async function pendingUser(withEmail: boolean) {
  const suffix = randomUUID().slice(0, 8);
  const email = withEmail ? `pending.${suffix}@example.test` : null;
  const role = await prisma.role.findUniqueOrThrow({
    where: { code: "cashier" },
  });
  const user = await prisma.user.create({
    data: {
      username: `pending.${suffix}`,
      usernameNormalized: `pending.${suffix}`,
      email,
      emailNormalized: email,
      displayName: "Pending B4 Staff",
      status: "PENDING_PASSWORD",
      passwordHash: null,
      passwordVersion: 0,
      roles: { create: { roleId: role.id } },
    },
  });
  users.push(user.id);
  return user;
}

async function activeUser(roleCode: string, withEmail: boolean) {
  const suffix = randomUUID().slice(0, 8);
  const email = withEmail ? `active.${suffix}@example.test` : null;
  const role = await prisma.role.findUniqueOrThrow({
    where: { code: roleCode },
  });
  const user = await prisma.user.create({
    data: {
      username: `b4.${suffix}`,
      usernameNormalized: `b4.${suffix}`,
      email,
      emailNormalized: email,
      displayName: "Active B4 Staff",
      status: "ACTIVE",
      passwordHash: await hashPassword(`active password ${randomUUID()}`),
      roles: { create: { roleId: role.id } },
    },
  });
  users.push(user.id);
  return user;
}

async function principal(roleCode: string) {
  const user = await activeUser(roleCode, false);
  const password = `principal password ${randomUUID()}`;
  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash: await hashPassword(password),
      passwordVersion: { increment: 1 },
    },
  });
  const claims = await authenticateCredentials({
    prisma,
    identifier: user.username,
    password,
    headers: new Headers({ "user-agent": "b4-integration" }),
  });
  if (!claims) throw new Error("Unable to authenticate B4 fixture.");
  return { userId: user.id, claims };
}
