import { describe, expect, it } from "vitest";

import {
  grantExpiresAt,
  issueCredentialGrantSchema,
  redeemCredentialGrantSchema,
} from "./credential-grant-policy";

describe("credential grant policy", () => {
  it("uses the approved immutable fifteen-minute lifetime", () => {
    const now = new Date("2026-10-15T00:00:00Z");
    expect(grantExpiresAt(now).getTime() - now.getTime()).toBe(15 * 60_000);
  });

  it("accepts only server-approved purposes, channels and attestation", () => {
    expect(
      issueCredentialGrantSchema.safeParse({
        userId: crypto.randomUUID(),
        purpose: "INITIAL_ENROLMENT",
        channel: "IN_PERSON",
        verificationAttestation:
          "STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED",
      }).success,
    ).toBe(true);
    expect(
      issueCredentialGrantSchema.safeParse({
        userId: crypto.randomUUID(),
        purpose: "PROTECTED_RECOVERY",
        channel: "IN_PERSON",
        verificationAttestation:
          "STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED",
      }).success,
    ).toBe(false);
  });

  it("bounds credentials and requires matching bounded passwords", () => {
    expect(
      redeemCredentialGrantSchema.safeParse({
        credential: "a".repeat(43),
        password: "a secure password",
        passwordConfirmation: "different password",
      }).success,
    ).toBe(false);
    expect(
      redeemCredentialGrantSchema.safeParse({
        credential: "a".repeat(97),
        password: "a secure password",
        passwordConfirmation: "a secure password",
      }).success,
    ).toBe(false);
  });
});
