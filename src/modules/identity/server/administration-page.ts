import { redirect } from "next/navigation";

import { AuthenticationRequiredError, PermissionDeniedError } from "./guards";
import { claimsFromCurrentCookies } from "./session-token";

export async function administrationPageClaims() {
  const claims = await claimsFromCurrentCookies();
  if (!claims) redirect("/login");
  return claims;
}

export function handleAdministrationPageError(error: unknown): never {
  if (error instanceof AuthenticationRequiredError) redirect("/login");
  if (error instanceof PermissionDeniedError) redirect("/forbidden");
  throw error;
}
