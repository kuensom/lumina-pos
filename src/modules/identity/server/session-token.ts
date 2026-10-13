import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { decode, getToken } from "next-auth/jwt";

import { authClaimsSchema, type AuthClaims } from "./auth-claims";

export async function claimsFromRequest(
  request: NextRequest,
): Promise<AuthClaims | null> {
  const token = await getToken({
    req: request,
    secret: requiredNextAuthSecret(),
  });
  return parseClaims(token);
}

export async function claimsFromCurrentCookies(): Promise<AuthClaims | null> {
  const cookieStore = await cookies();
  const tokenValue =
    cookieStore.get("__Secure-next-auth.session-token")?.value ??
    cookieStore.get("next-auth.session-token")?.value;
  if (!tokenValue) return null;
  try {
    const token = await decode({
      token: tokenValue,
      secret: requiredNextAuthSecret(),
    });
    return parseClaims(token);
  } catch {
    return null;
  }
}

export async function clearSessionCookies(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete("__Secure-next-auth.session-token");
  cookieStore.delete("next-auth.session-token");
}

function parseClaims(value: unknown): AuthClaims | null {
  const result = authClaimsSchema.safeParse(value);
  return result.success ? result.data : null;
}

function requiredNextAuthSecret(): string {
  const value = process.env.NEXTAUTH_SECRET;
  if (!value || Buffer.byteLength(value) < 32) {
    throw new Error("NEXTAUTH_SECRET must contain at least 32 bytes.");
  }
  return value;
}
