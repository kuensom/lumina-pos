import { z } from "zod";

export const authClaimsSchema = z.object({
  sub: z.string().uuid(),
  displayName: z.string().min(1).max(120),
  sessionId: z.string().uuid(),
  sessionBinding: z.string().min(40).max(100),
  authzVersion: z.number().int().positive(),
  signedInAt: z.number().int().nonnegative(),
  absoluteExpiresAt: z.number().int().positive(),
});

export type AuthClaims = z.infer<typeof authClaimsSchema>;
