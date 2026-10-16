import { randomUUID } from "node:crypto";

import type { PrismaClient } from "@prisma/client";

import {
  normalizeOptionalEmail,
  normalizeUsername,
  PASSWORD_MAX_CHARACTERS,
  PASSWORD_MIN_CHARACTERS,
} from "../domain/identity-policy";
import {
  admitLoginAttempt,
  findLoginCandidate,
  isLoginRateLimited,
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
export const MAX_LOGIN_IDENTIFIER_CODE_UNITS = 320;
export const MAX_LOGIN_PASSWORD_CODE_UNITS = 128;

export async function authenticateCredentials(input: {
  prisma: PrismaClient;
  identifier: unknown;
  password: unknown;
  headers: HeaderSource;
  now?: Date;
}): Promise<CreatedAuthenticationSession | null> {
  const now = input.now ?? new Date();
  const correlationId = randomUUID();
  if (!hasBoundedCredentialFields(input.identifier, input.password)) {
    return null;
  }
  const parsed = parseIdentifier(input.identifier);
  const password = input.password as string;
  const network = trustedNetworkIdentifier(input.headers);
  const rateKey = rateLimitDigestKey();
  const identifierHash = digestSecret("rate-limit", parsed.normalized, rateKey);
  const networkHash = network
    ? digestSecret("rate-limit", network, rateKey)
    : null;
  // This read is an optimization only. The advisory-locked admission
  // transaction repeats the decision and remains authoritative.
  if (
    await isLoginRateLimited(input.prisma, identifierHash, networkHash, now)
  ) {
    return null;
  }
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

  const sessionBinding = generateOpaqueSessionBinding();
  const session = await retrySerializableTransaction(() =>
    admitLoginAttempt({
      prisma: input.prisma,
      candidate,
      credentialsValid:
        parsed.valid &&
        passwordShapeValid &&
        candidate?.status === "ACTIVE" &&
        Boolean(candidate.passwordHash) &&
        passwordValid,
      identifierKind: parsed.valid ? parsed.kind : "invalid",
      sessionBinding,
      sessionDigestKey: sessionDigestKey(),
      identifierHash,
      networkHash,
      userAgentSummary: userAgentSummary(input.headers),
      now,
      correlationId,
    }),
  );
  if (!session || !candidate) return null;
  return {
    id: candidate.id,
    sub: candidate.id,
    displayName: session.displayName,
    sessionId: session.sessionId,
    sessionBinding,
    authzVersion: session.authzVersion,
    passwordVersion: session.passwordVersion,
    signedInAt: now.getTime(),
    absoluteExpiresAt: session.absoluteExpiresAt.getTime(),
  };
}

function hasBoundedCredentialFields(
  identifier: unknown,
  password: unknown,
): identifier is string {
  return (
    typeof identifier === "string" &&
    typeof password === "string" &&
    identifier.length <= MAX_LOGIN_IDENTIFIER_CODE_UNITS &&
    password.length <= MAX_LOGIN_PASSWORD_CODE_UNITS
  );
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
