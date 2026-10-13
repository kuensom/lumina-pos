import { listRoles } from "@/modules/identity/application/administration-service";
import { redirect } from "next/navigation";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import { createRoleAction } from "@/modules/identity/server/administration-actions";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";
import { AdministrationForm } from "@/modules/identity/ui/administration-form";

export default async function NewRolePage() {
  const claims = await administrationPageClaims();
  let result;
  try {
    result = await listRoles({ prisma, claims });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  if (result.viewer !== "super_administrator") redirect("/forbidden");
  const permissions = result.permissions.filter(
    ({ requiresSuperAdmin }) => !requiresSuperAdmin,
  );
  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:px-8">
      <h1 className="text-3xl font-bold">Create configurable role</h1>
      <AdministrationForm
        action={createRoleAction}
        submitLabel="Create role"
        className="mt-6 space-y-5 rounded-xl bg-white p-6 shadow-sm"
      >
        <RoleField
          name="code"
          label="Immutable role code"
          maxLength={80}
          required
        />
        <RoleField name="name" label="Role name" maxLength={120} required />
        <RoleField name="description" label="Description" maxLength={500} />
        <fieldset>
          <legend className="font-semibold">Permissions</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {permissions.map((permission) => (
              <label key={permission.id} className="flex gap-2">
                <input
                  type="checkbox"
                  name="permissionIds"
                  value={permission.id}
                />
                {permission.code}
              </label>
            ))}
          </div>
        </fieldset>
      </AdministrationForm>
    </main>
  );
}

function RoleField({
  name,
  label,
  maxLength,
  required = false,
}: {
  name: string;
  label: string;
  maxLength: number;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium">{label}</span>
      <input
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
        name={name}
        maxLength={maxLength}
        required={required}
      />
    </label>
  );
}
