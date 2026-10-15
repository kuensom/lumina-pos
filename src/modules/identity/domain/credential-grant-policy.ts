import { z } from "zod";

export const GRANT_LIFETIME_MINUTES = 15;
export const CREDENTIAL_BYTES = 32;
export const MAX_CREDENTIAL_LENGTH = 96;
export const IDENTITY_VERIFICATION_ATTESTATION =
  "STAFF_RECORD_AND_MANAGER_ATTESTATION_CONFIRMED";

export const issueCredentialGrantSchema = z
  .object({
    userId: z.string().uuid(),
    purpose: z.enum(["INITIAL_ENROLMENT", "ADMINISTRATOR_RESET"]),
    channel: z.enum(["EMAIL", "IN_PERSON"]),
    verificationAttestation: z.literal(IDENTITY_VERIFICATION_ATTESTATION),
  })
  .strict();

export const redeemCredentialGrantSchema = z
  .object({
    credential: z.string().min(40).max(MAX_CREDENTIAL_LENGTH),
    password: z.string().max(128),
    passwordConfirmation: z.string().max(128),
  })
  .strict()
  .refine((value) => value.password === value.passwordConfirmation, {
    message: "Passwords do not match.",
  });

export function grantExpiresAt(now: Date): Date {
  return new Date(now.getTime() + GRANT_LIFETIME_MINUTES * 60_000);
}

export const GENERIC_CREDENTIAL_FAILURE =
  "This setup credential is invalid, expired, or has already been used.";
