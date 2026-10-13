import { listRoles } from "@/modules/identity/application/administration-service";
import { isOperationalRole } from "@/modules/identity/domain/administration-policy";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import { createStaffAction } from "@/modules/identity/server/administration-actions";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";
import { AdministrationForm } from "@/modules/identity/ui/administration-form";

export default async function NewStaffPage() {
  const claims = await administrationPageClaims();
  let catalogue;
  try {
    catalogue = await listRoles({ prisma, claims });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  const operationalRoles = catalogue.roles.filter(isOperationalRole);
  return (
    <main className="mx-auto w-full max-w-2xl px-5 py-10 sm:px-8">
      <h1 className="text-3xl font-bold">Create staff account</h1>
      <p className="mt-2 text-slate-700">
        The account will await password enrollment and cannot sign in yet.
      </p>
      <AdministrationForm
        action={createStaffAction}
        submitLabel="Create staff account"
        className="mt-6 space-y-5 rounded-xl bg-white p-6 shadow-sm"
      >
        <TextField name="username" label="Username" maxLength={32} required />
        <TextField
          name="displayName"
          label="Display name"
          maxLength={120}
          required
        />
        <TextField
          name="email"
          label="Email (optional)"
          type="email"
          maxLength={320}
        />
        <fieldset>
          <legend className="font-semibold">Operational roles</legend>
          <div className="mt-2 space-y-2">
            {operationalRoles.map((role) => (
              <label key={role.id} className="flex gap-2">
                <input type="checkbox" name="roleIds" value={role.id} />
                {role.name}
              </label>
            ))}
          </div>
        </fieldset>
      </AdministrationForm>
    </main>
  );
}

function TextField({
  name,
  label,
  type = "text",
  maxLength,
  required = false,
}: {
  name: string;
  label: string;
  type?: string;
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
        maxLength={maxLength}
        required={required}
      />
    </label>
  );
}
