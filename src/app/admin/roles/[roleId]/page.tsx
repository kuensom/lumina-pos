import { notFound } from "next/navigation";

import { listRoles } from "@/modules/identity/application/administration-service";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  changeRoleStatusAction,
  replaceRolePermissionsAction,
  updateRoleAction,
} from "@/modules/identity/server/administration-actions";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";
import { AdministrationForm } from "@/modules/identity/ui/administration-form";

export default async function RoleDetailPage({
  params,
}: {
  params: Promise<{ roleId: string }>;
}) {
  const { roleId } = await params;
  const claims = await administrationPageClaims();
  let result;
  try {
    result = await listRoles({ prisma, claims });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  const role = result.roles.find(({ id }) => id === roleId);
  if (!role) notFound();
  const configurable =
    result.viewer === "super_administrator" &&
    !role.isSystem &&
    !role.isProtected;
  const updatedAt = role.updatedAt.toISOString();
  const permissions = result.permissions.filter(
    ({ requiresSuperAdmin }) => !requiresSuperAdmin,
  );

  return (
    <main className="mx-auto w-full max-w-4xl px-5 py-10 sm:px-8">
      <p className="text-sm font-semibold uppercase tracking-wider text-forest">
        Role
      </p>
      <h1 className="text-3xl font-bold">{role.name}</h1>
      <p className="mt-1 text-slate-600">
        {role.code} · {role.isActive ? "Active" : "Inactive"} ·{" "}
        {role._count.users} assigned staff
      </p>
      {configurable ? (
        <div className="mt-8 grid gap-6 lg:grid-cols-2">
          <Section title="Role details">
            <AdministrationForm
              action={updateRoleAction}
              submitLabel="Save details"
            >
              <Hidden roleId={role.id} updatedAt={updatedAt} />
              <Field
                name="name"
                label="Name"
                defaultValue={role.name}
                required
              />
              <Field
                name="description"
                label="Description"
                defaultValue={role.description ?? ""}
              />
            </AdministrationForm>
          </Section>
          <Section title="Status">
            <AdministrationForm
              action={changeRoleStatusAction}
              submitLabel="Change status"
            >
              <Hidden roleId={role.id} updatedAt={updatedAt} />
              <label className="block">
                <span className="text-sm font-medium">New status</span>
                <select
                  name="isActive"
                  defaultValue={String(role.isActive)}
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
                >
                  <option value="true">Active</option>
                  <option value="false">Inactive</option>
                </select>
              </label>
              <Field name="reason" label="Reason" required />
            </AdministrationForm>
          </Section>
          <Section title="Permissions">
            <AdministrationForm
              action={replaceRolePermissionsAction}
              submitLabel="Save permissions"
            >
              <Hidden roleId={role.id} updatedAt={updatedAt} />
              <fieldset>
                <legend className="font-semibold">Allowed capabilities</legend>
                <div className="mt-2 grid gap-2">
                  {permissions.map((permission) => (
                    <label key={permission.id} className="flex gap-2">
                      <input
                        type="checkbox"
                        name="permissionIds"
                        value={permission.id}
                        defaultChecked={role.permissions.some(
                          (entry) => entry.permissionId === permission.id,
                        )}
                      />
                      {permission.code}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Field
                name="reason"
                label="Reason (required when removing access)"
              />
            </AdministrationForm>
          </Section>
        </div>
      ) : (
        <section className="mt-8 rounded-xl bg-white p-5 shadow-sm">
          <h2 className="text-xl font-bold">System role</h2>
          <p className="mt-2 text-slate-700">
            System role codes, details, status, and protected capabilities are
            read-only here.
          </p>
          <ul className="mt-4 list-disc pl-5">
            {role.permissions.map(({ permission }) => (
              <li key={permission.id}>{permission.code}</li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}

function Hidden({ roleId, updatedAt }: { roleId: string; updatedAt: string }) {
  return (
    <>
      <input type="hidden" name="roleId" value={roleId} />
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
  defaultValue,
  required = false,
}: {
  name: string;
  label: string;
  defaultValue?: string;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium">{label}</span>
      <input
        name={name}
        defaultValue={defaultValue}
        maxLength={500}
        required={required}
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
      />
    </label>
  );
}
