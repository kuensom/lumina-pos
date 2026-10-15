import { z } from "zod";

export const authClaimsSchema = z.object({
  sub: z.string().uuid(),
  displayName: z.string().min(1).max(120),
  sessionId: z.string().uuid(),
  sessionBinding: z.string().min(40).max(100),
  authzVersion: z.number().int().positive(),
  // Migration backfills pre-B4 sessions and JWTs to version one. Remove this
  // compatibility default after every pre-B4 cookie has exceeded 12 hours.
  passwordVersion: z.number().int().positive().default(1),
  signedInAt: z.number().int().nonnegative(),
  absoluteExpiresAt: z.number().int().positive(),
});

export type AuthClaims = z.infer<typeof authClaimsSchema>;
