"use server";

import { headers } from "next/headers";
import { revalidatePath } from "next/cache";

import {
  changeRoleStatus,
  changeStaffStatus,
  changeUsername,
  createRole,
  createStaff,
  recordProtectedAdministrationDenial,
  replaceRolePermissions,
  replaceUserRoles,
  updateRole,
  updateStaffProfile,
} from "../application/administration-service";
import { AdministrationPolicyError } from "../domain/administration-policy";
import { prisma } from "../infrastructure/prisma";
import { assertSameOrigin } from "../security/request-security";
import { claimsFromCurrentCookies } from "./session-token";

export type AdministrationActionState = {
  ok: boolean;
  message: string;
};

const initialFailure: AdministrationActionState = {
  ok: false,
  message: "The request could not be completed.",
};

export async function createStaffAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  return run(async () => {
    const claims = await requestClaims();
    await createStaff({
      prisma,
      claims,
      command: {
        username: value(data, "username"),
        email: value(data, "email"),
        displayName: value(data, "displayName"),
        roleIds: values(data, "roleIds"),
      },
    });
    revalidatePath("/admin/staff");
    return success(
      "Staff account created. Password enrollment is still required.",
    );
  });
}

export async function updateOrdinaryStaffAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return profileAction("ordinary", state, data);
}
export async function updateProtectedStaffAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return profileAction("protected", state, data);
}
export async function changeOrdinaryStaffStatusAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return statusAction("ordinary", state, data);
}
export async function changeProtectedStaffStatusAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return statusAction("protected", state, data);
}
export async function replaceOperationalRolesAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return roleAssignmentAction("ordinary", state, data);
}
export async function replacePrivilegedRolesAction(
  state: AdministrationActionState,
  data: FormData,
) {
  return roleAssignmentAction("protected", state, data);
}

export async function changeUsernameAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  let claims: Awaited<ReturnType<typeof requestClaims>> | undefined;
  return run(
    async () => {
      claims = await requestClaims();
      const userId = value(data, "userId");
      await changeUsername({
        prisma,
        claims,
        command: {
          userId,
          username: value(data, "username"),
          reason: value(data, "reason"),
          expectedUpdatedAt: value(data, "expectedUpdatedAt"),
        },
      });
      revalidatePath(`/admin/staff/${userId}`);
      revalidatePath("/admin/staff");
      return success("Username changed. Existing sessions were revoked.");
    },
    denialRecorder(
      () => claims,
      "user",
      () => value(data, "userId"),
    ),
  );
}

export async function createRoleAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  return run(async () => {
    const claims = await requestClaims();
    await createRole({
      prisma,
      claims,
      command: {
        code: value(data, "code"),
        name: value(data, "name"),
        description: value(data, "description"),
        permissionIds: values(data, "permissionIds"),
      },
    });
    revalidatePath("/admin/roles");
    return success("Role created.");
  });
}

export async function updateRoleAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  return run(async () => {
    const claims = await requestClaims();
    const roleId = value(data, "roleId");
    await updateRole({
      prisma,
      claims,
      command: {
        roleId,
        name: value(data, "name"),
        description: value(data, "description"),
        expectedUpdatedAt: value(data, "expectedUpdatedAt"),
      },
    });
    revalidatePath(`/admin/roles/${roleId}`);
    revalidatePath("/admin/roles");
    return success("Role details updated.");
  });
}

export async function changeRoleStatusAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  return run(async () => {
    const claims = await requestClaims();
    const roleId = value(data, "roleId");
    await changeRoleStatus({
      prisma,
      claims,
      command: {
        roleId,
        isActive: value(data, "isActive") === "true",
        reason: value(data, "reason"),
        expectedUpdatedAt: value(data, "expectedUpdatedAt"),
      },
    });
    revalidatePath(`/admin/roles/${roleId}`);
    revalidatePath("/admin/roles");
    return success("Role status updated. Affected sessions were revoked.");
  });
}

export async function replaceRolePermissionsAction(
  _state: AdministrationActionState,
  data: FormData,
) {
  return run(async () => {
    const claims = await requestClaims();
    const roleId = value(data, "roleId");
    await replaceRolePermissions({
      prisma,
      claims,
      command: {
        roleId,
        permissionIds: values(data, "permissionIds"),
        reason: value(data, "reason"),
        expectedUpdatedAt: value(data, "expectedUpdatedAt"),
      },
    });
    revalidatePath(`/admin/roles/${roleId}`);
    return success("Role permissions updated. Affected sessions were revoked.");
  });
}

async function profileAction(
  authority: "ordinary" | "protected",
  _state: AdministrationActionState,
  data: FormData,
) {
  let claims: Awaited<ReturnType<typeof requestClaims>> | undefined;
  return run(
    async () => {
      claims = await requestClaims();
      const userId = value(data, "userId");
      await updateStaffProfile({
        prisma,
        claims,
        authority,
        command: {
          userId,
          displayName: value(data, "displayName"),
          email: value(data, "email"),
          reason: value(data, "reason"),
          expectedUpdatedAt: value(data, "expectedUpdatedAt"),
        },
      });
      revalidatePath(`/admin/staff/${userId}`);
      revalidatePath("/admin/staff");
      return success("Staff profile updated. Existing sessions were revoked.");
    },
    authority === "protected"
      ? denialRecorder(
          () => claims,
          "user",
          () => value(data, "userId"),
        )
      : undefined,
  );
}

async function statusAction(
  authority: "ordinary" | "protected",
  _state: AdministrationActionState,
  data: FormData,
) {
  let claims: Awaited<ReturnType<typeof requestClaims>> | undefined;
  return run(
    async () => {
      claims = await requestClaims();
      const userId = value(data, "userId");
      await changeStaffStatus({
        prisma,
        claims,
        authority,
        command: {
          userId,
          action: value(data, "action") as
            | "activate"
            | "deactivate"
            | "lock"
            | "unlock",
          reason: value(data, "reason"),
          expectedUpdatedAt: value(data, "expectedUpdatedAt"),
        },
      });
      revalidatePath(`/admin/staff/${userId}`);
      revalidatePath("/admin/staff");
      return success("Account status updated. Existing sessions were revoked.");
    },
    authority === "protected"
      ? denialRecorder(
          () => claims,
          "user",
          () => value(data, "userId"),
        )
      : undefined,
  );
}

async function roleAssignmentAction(
  authority: "ordinary" | "protected",
  _state: AdministrationActionState,
  data: FormData,
) {
  let claims: Awaited<ReturnType<typeof requestClaims>> | undefined;
  return run(
    async () => {
      claims = await requestClaims();
      const userId = value(data, "userId");
      await replaceUserRoles({
        prisma,
        claims,
        authority,
        command: {
          userId,
          roleIds: values(data, "roleIds"),
          reason: value(data, "reason"),
          expectedUpdatedAt: value(data, "expectedUpdatedAt"),
        },
      });
      revalidatePath(`/admin/staff/${userId}`);
      revalidatePath("/admin/staff");
      return success(
        "Role assignments updated. Existing sessions were revoked.",
      );
    },
    authority === "protected"
      ? denialRecorder(
          () => claims,
          "user",
          () => value(data, "userId"),
        )
      : undefined,
  );
}

async function requestClaims() {
  assertSameOrigin(await headers());
  const claims = await claimsFromCurrentCookies();
  if (!claims) throw new Error("Authentication required.");
  return claims;
}

async function run(
  operation: () => Promise<AdministrationActionState>,
  onPolicyError?: (error: AdministrationPolicyError) => Promise<void>,
): Promise<AdministrationActionState> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof AdministrationPolicyError) {
      if (onPolicyError) await onPolicyError(error).catch(() => undefined);
      return { ok: false, message: error.message };
    }
    if (error instanceof Error && error.name === "ZodError") {
      return { ok: false, message: "Review the highlighted form values." };
    }
    return initialFailure;
  }
}

function denialRecorder(
  claims: () => Awaited<ReturnType<typeof requestClaims>> | undefined,
  targetType: "user" | "role",
  targetId: () => string,
) {
  return async (error: AdministrationPolicyError) => {
    const currentClaims = claims();
    if (!currentClaims) return;
    await recordProtectedAdministrationDenial({
      prisma,
      claims: currentClaims,
      targetType,
      targetId: targetId() || null,
      reasonCode: error.code,
    });
  };
}

function value(data: FormData, name: string) {
  const entry = data.get(name);
  return typeof entry === "string" ? entry : "";
}

function values(data: FormData, name: string) {
  return data
    .getAll(name)
    .filter((entry): entry is string => typeof entry === "string");
}

function success(message: string): AdministrationActionState {
  return { ok: true, message };
}
