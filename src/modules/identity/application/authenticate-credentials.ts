import { randomUUID } from "node:crypto";

import type { PrismaClient } from "@prisma/client";

import {
  normalizeOptionalEmail,
  normalizeUsername,
  PASSWORD_MAX_CHARACTERS,
  PASSWORD_MIN_CHARACTERS,
} from "../domain/identity-policy";
import {
  createLoginSession,
  findLoginCandidate,
  isLoginRateLimited,
  recordLoginFailure,
} from "../infrastructure/authentication-repository";
import { retrySerializableTransaction } from "../infrastructure/serializable-retry";
import {
  generateOpaqueSessionBinding,
  rateLimitDigestKey,
  sessionDigestKey,
} from "../security/auth-secrets";
import { verifyPassword } from "../security/password";
import {
  type HeaderSource,
  trustedNetworkIdentifier,
  userAgentSummary,
} from "../security/request-security";
import { digestSecret } from "../security/secret-digest";
import type { CreatedAuthenticationSession } from "./authentication-types";

// This is a timing equalizer, not an account credential. It was generated with
// the same Argon2id policy as real password hashes.
const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$NN6KgqBF44kjOstTg0ogjg$xNeVxssKd4yD+ukJqhNkdu8GqR+zr0vzVcetDPKktN0";

export async function authenticateCredentials(input: {
  prisma: PrismaClient;
  identifier: unknown;
  password: unknown;
  headers: HeaderSource;
  now?: Date;
}): Promise<CreatedAuthenticationSession | null> {
  const now = input.now ?? new Date();
  const correlationId = randomUUID();
  const parsed = parseIdentifier(input.identifier);
  const password = typeof input.password === "string" ? input.password : "";
  const network = trustedNetworkIdentifier(input.headers);
  const rateKey = rateLimitDigestKey();
  const identifierHash = digestSecret("rate-limit", parsed.normalized, rateKey);
  const networkHash = digestSecret("rate-limit", network, rateKey);

  const rateLimited = await isLoginRateLimited(
    input.prisma,
    identifierHash,
    networkHash,
    now,
  );
  const candidate = parsed.valid
    ? await findLoginCandidate(input.prisma, parsed.normalized, parsed.kind)
    : null;
  const passwordLength = Array.from(password).length;
  const passwordShapeValid =
    passwordLength >= PASSWORD_MIN_CHARACTERS &&
    passwordLength <= PASSWORD_MAX_CHARACTERS;
  const passwordValid = await verifyPassword(
    candidate?.passwordHash ?? DUMMY_PASSWORD_HASH,
    password,
  );

  if (
    rateLimited ||
    !parsed.valid ||
    !passwordShapeValid ||
    !candidate ||
    candidate.status !== "ACTIVE" ||
    !candidate.passwordHash ||
    !passwordValid
  ) {
    await recordLoginFailure({
      prisma: input.prisma,
      identifierHash,
      networkHash,
      identifierKind: parsed.valid ? parsed.kind : "invalid",
      now,
      correlationId,
    });
    return null;
  }

  const sessionBinding = generateOpaqueSessionBinding();
  try {
    const session = await retrySerializableTransaction(() =>
      createLoginSession({
        prisma: input.prisma,
        candidate,
        sessionBinding,
        sessionDigestKey: sessionDigestKey(),
        identifierHash,
        networkHash,
        userAgentSummary: userAgentSummary(input.headers),
        now,
        correlationId,
      }),
    );
    return {
      id: candidate.id,
      sub: candidate.id,
      displayName: session.displayName,
      sessionId: session.sessionId,
      sessionBinding,
      authzVersion: session.authzVersion,
      signedInAt: now.getTime(),
      absoluteExpiresAt: session.absoluteExpiresAt.getTime(),
    };
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message === "LOGIN_STATE_CHANGED" ||
        error.message === "LOGIN_RATE_LIMITED")
    ) {
      await recordLoginFailure({
        prisma: input.prisma,
        identifierHash,
        networkHash,
        identifierKind: parsed.kind,
        now,
        correlationId,
      });
      return null;
    }
    throw error;
  }
}

function parseIdentifier(
  identifier: unknown,
):
  | { valid: true; kind: "username" | "email"; normalized: string }
  | { valid: false; kind: "username"; normalized: string } {
  if (typeof identifier !== "string") {
    return { valid: false, kind: "username", normalized: "invalid" };
  }
  const trimmed = identifier.trim();
  try {
    if (trimmed.includes("@")) {
      const normalized = normalizeOptionalEmail(trimmed);
      if (!normalized) throw new Error("Invalid email.");
      return { valid: true, kind: "email", normalized };
    }
    return {
      valid: true,
      kind: "username",
      normalized: normalizeUsername(trimmed),
    };
  } catch {
    return {
      valid: false,
      kind: "username",
      normalized: trimmed.toLowerCase().slice(0, 320) || "invalid",
    };
  }
}
