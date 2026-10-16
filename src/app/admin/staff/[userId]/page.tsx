import { notFound } from "next/navigation";
import Link from "next/link";

import {
  getStaffDetail,
  listRoles,
} from "@/modules/identity/application/administration-service";
import { isOperationalRole } from "@/modules/identity/domain/administration-policy";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  changeOrdinaryStaffStatusAction,
  changeProtectedStaffStatusAction,
  changeUsernameAction,
  replaceOperationalRolesAction,
  replacePrivilegedRolesAction,
  updateOrdinaryStaffAction,
  updateProtectedStaffAction,
} from "@/modules/identity/server/administration-actions";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";
import { AdministrationForm } from "@/modules/identity/ui/administration-form";

export default async function StaffDetailPage({
  params,
}: {
  params: Promise<{ userId: string }>;
}) {
  const { userId } = await params;
  const claims = await administrationPageClaims();
  let detail;
  try {
    detail = await getStaffDetail({ prisma, claims, userId });
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === "NOT_FOUND"
    ) {
      notFound();
    }
    handleAdministrationPageError(error);
  }
  const protectedAccount = detail.user.roles.some(
    (role) => role.code === "super_administrator" && role.isProtected,
  );
  const canManage = detail.viewer !== "supervisor";
  const canManageProtected = detail.viewer === "super_administrator";
  let roles: Awaited<ReturnType<typeof listRoles>>["roles"] = [];
  if (canManage) {
    try {
      roles = (await listRoles({ prisma, claims })).roles;
    } catch (error) {
      handleAdministrationPageError(error);
    }
  }
  const assignableRoles = canManageProtected
    ? roles.filter((role) => role.isActive)
    : roles.filter(isOperationalRole);
  const profileAction = protectedAccount
    ? updateProtectedStaffAction
    : updateOrdinaryStaffAction;
  const statusAction = protectedAccount
    ? changeProtectedStaffStatusAction
    : changeOrdinaryStaffStatusAction;
  const assignmentAction = canManageProtected
    ? replacePrivilegedRolesAction
    : replaceOperationalRolesAction;
  const updatedAt = detail.user.updatedAt.toISOString();

  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-10 sm:px-8">
      <p className="text-sm font-semibold uppercase tracking-wider text-forest">
        Staff account
      </p>
      <h1 className="text-3xl font-bold">{detail.user.displayName}</h1>
      <dl className="mt-5 grid gap-3 rounded-xl bg-white p-5 shadow-sm sm:grid-cols-2">
        <div>
          <dt className="text-sm text-slate-600">Username</dt>
          <dd>{detail.user.username}</dd>
        </div>
        <div>
          <dt className="text-sm text-slate-600">Status</dt>
          <dd>{detail.user.status.replaceAll("_", " ")}</dd>
        </div>
        {detail.user.email !== undefined ? (
          <div>
            <dt className="text-sm text-slate-600">Email</dt>
            <dd>{detail.user.email ?? "Not provided"}</dd>
          </div>
        ) : null}
        <div>
          <dt className="text-sm text-slate-600">Roles</dt>
          <dd>
            {detail.user.roles.map((role) => role.name).join(", ") ||
              "No roles"}
          </dd>
        </div>
      </dl>
      {canManage ? (
        <Link
          href={`/admin/staff/${userId}/credentials`}
          className="mt-5 inline-block rounded-lg bg-forest px-4 py-2 font-semibold text-white no-underline"
        >
          Manage password enrollment or recovery
        </Link>
      ) : null}

      {canManage ? (
        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <Section title="Profile">
            <AdministrationForm
              action={profileAction}
              submitLabel="Save profile"
            >
              <HiddenIdentity userId={userId} updatedAt={updatedAt} />
              <Field
                name="displayName"
                label="Display name"
                defaultValue={detail.user.displayName}
                maxLength={120}
                required
              />
              <Field
                name="email"
                label="Email (optional)"
                type="email"
                defaultValue={detail.user.email ?? ""}
                maxLength={320}
              />
              {protectedAccount ? (
                <Field name="reason" label="Reason" maxLength={500} required />
              ) : null}
            </AdministrationForm>
          </Section>

          <Section title="Account status">
            {detail.user.status === "PENDING_PASSWORD" ? (
              <p className="mb-3 text-sm text-amber-800">
                Activation is unavailable until password enrollment is complete.
              </p>
            ) : null}
            <AdministrationForm
              action={statusAction}
              submitLabel="Apply status change"
            >
              <HiddenIdentity userId={userId} updatedAt={updatedAt} />
              <label className="block">
                <span className="text-sm font-medium">Action</span>
                <select
                  name="action"
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
                  required
                >
                  <option value="activate">Activate</option>
                  <option value="deactivate">Deactivate</option>
                  <option value="lock">Lock</option>
                  <option value="unlock">Unlock</option>
                </select>
              </label>
              <Field
                name="reason"
                label="Administrative reason"
                maxLength={500}
                required={protectedAccount}
              />
            </AdministrationForm>
          </Section>

          <Section title="Role assignments">
            <AdministrationForm
              action={assignmentAction}
              submitLabel="Save role assignments"
            >
              <HiddenIdentity userId={userId} updatedAt={updatedAt} />
              <fieldset>
                <legend className="font-semibold">Available roles</legend>
                <div className="mt-2 space-y-2">
                  {assignableRoles.map((role) => (
                    <label key={role.id} className="flex gap-2">
                      <input
                        type="checkbox"
                        name="roleIds"
                        value={role.id}
                        defaultChecked={detail.user.roles.some(
                          ({ id }) => id === role.id,
                        )}
                      />
                      {role.name}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Field
                name="reason"
                label="Reason (required when removing a role)"
                maxLength={500}
              />
            </AdministrationForm>
          </Section>

          {canManageProtected ? (
            <Section title="Protected username change">
              <p className="mb-3 text-sm text-slate-700">
                Requires recent Super Administrator authentication and revokes
                every target session.
              </p>
              <AdministrationForm
                action={changeUsernameAction}
                submitLabel="Change username"
              >
                <HiddenIdentity userId={userId} updatedAt={updatedAt} />
                <Field
                  name="username"
                  label="New username"
                  defaultValue={detail.user.username}
                  maxLength={32}
                  required
                />
                <Field name="reason" label="Reason" maxLength={500} required />
              </AdministrationForm>
            </Section>
          ) : null}
        </div>
      ) : null}
    </main>
  );
}

function HiddenIdentity({
  userId,
  updatedAt,
}: {
  userId: string;
  updatedAt: string;
}) {
  return (
    <>
      <input type="hidden" name="userId" value={userId} />
      <input type="hidden" name="expectedUpdatedAt" value={updatedAt} />
    </>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl bg-white p-5 shadow-sm">
      <h2 className="mb-4 text-xl font-bold">{title}</h2>
      {children}
    </section>
  );
}

function Field({
  name,
  label,
  type = "text",
  defaultValue,
  maxLength,
  required = false,
}: {
  name: string;
  label: string;
  type?: string;
  defaultValue?: string;
  maxLength: number;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium">{label}</span>
      <input
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
        name={name}
        type={type}
        defaultValue={defaultValue}
        maxLength={maxLength}
        required={required}
      />
    </label>
  );
}
