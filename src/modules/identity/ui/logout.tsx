import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { revokeSessionForLogout } from "../application/revoke-session";
import { prisma } from "../infrastructure/prisma";
import { assertSameOrigin } from "../security/request-security";
import {
  claimsFromCurrentCookies,
  clearSessionCookies,
} from "../server/session-token";

export async function logoutAction(): Promise<never> {
  "use server";

  assertSameOrigin(await headers());
  const claims = await claimsFromCurrentCookies();
  if (claims) {
    // NextAuth v4 swallows signOut event failures and clears the cookie. Commit
    // authoritative revocation first, then remove the browser credential.
    await revokeSessionForLogout({ prisma, claims });
  }
  await clearSessionCookies();
  redirect("/login");
}

export function LogoutButton() {
  return (
    <form action={logoutAction}>
      <button
        type="submit"
        className="rounded-lg border border-emerald-200 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-900"
      >
        Sign out
      </button>
    </form>
  );
}
