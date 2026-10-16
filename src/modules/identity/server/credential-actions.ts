"use server";

import { headers } from "next/headers";
import { revalidatePath } from "next/cache";

import {
  issueCredentialGrant,
  redeemCredentialGrant,
} from "../application/credential-grant-service";
import { prisma } from "../infrastructure/prisma";
import { assertSameOrigin } from "../security/request-security";
import { credentialIssueCommandFromFormData } from "./credential-action-input";
import { claimsFromCurrentCookies } from "./session-token";

export type CredentialActionState = {
  ok: boolean;
  message: string;
  voucher?: string;
};

export async function issueCredentialAction(
  _state: CredentialActionState,
  data: FormData,
): Promise<CredentialActionState> {
  try {
    assertSameOrigin(await headers());
    const claims = await claimsFromCurrentCookies();
    if (!claims) throw new Error("Authentication required.");
    const result = await issueCredentialGrant({
      prisma,
      claims,
      command: credentialIssueCommandFromFormData(data),
    });
    revalidatePath(`/admin/staff/${value(data, "userId")}/credentials`);
    return result.voucher
      ? {
          ok: true,
          message:
            "Voucher created. Reveal and hand it over once; it cannot be recovered later.",
          voucher: result.voucher,
        }
      : {
          ok: true,
          message:
            "Email invitation queued. Production delivery remains disabled until provider approval.",
        };
  } catch {
    return {
      ok: false,
      message: "The credential request could not be completed.",
    };
  }
}

export async function redeemCredentialAction(
  _state: CredentialActionState,
  data: FormData,
): Promise<CredentialActionState> {
  try {
    assertSameOrigin(await headers());
    const result = await redeemCredentialGrant({
      prisma,
      headers: await headers(),
      command: {
        credential: value(data, "credential"),
        password: value(data, "password"),
        passwordConfirmation: value(data, "passwordConfirmation"),
      },
    });
    return result.ok
      ? { ok: true, message: "Password saved. Sign in with your new password." }
      : result;
  } catch {
    return {
      ok: false,
      message:
        "This setup credential is invalid, expired, or has already been used.",
    };
  }
}

function value(data: FormData, name: string) {
  const entry = data.get(name);
  return typeof entry === "string" ? entry : "";
}
