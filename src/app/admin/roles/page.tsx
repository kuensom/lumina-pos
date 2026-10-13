import Link from "next/link";

import { listRoles } from "@/modules/identity/application/administration-service";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";

export default async function RolesPage() {
  const claims = await administrationPageClaims();
  let result;
  try {
    result = await listRoles({ prisma, claims });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  return (
    <main className="mx-auto w-full max-w-5xl px-5 py-10 sm:px-8">
      <div className="flex items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-forest">
            Administration
          </p>
          <h1 className="text-3xl font-bold">Roles and permissions</h1>
        </div>
        {result.viewer === "super_administrator" ? (
          <Link
            href="/admin/roles/new"
            className="rounded-lg bg-forest px-4 py-2 text-white"
          >
            Create configurable role
          </Link>
        ) : null}
      </div>
      <ul className="mt-6 grid gap-4 sm:grid-cols-2">
        {result.roles.map((role) => (
          <li key={role.id} className="rounded-xl bg-white p-5 shadow-sm">
            <Link
              href={`/admin/roles/${role.id}`}
              className="text-lg font-bold text-forest underline"
            >
              {role.name}
            </Link>
            <p className="text-sm text-slate-600">{role.code}</p>
            <p className="mt-2">
              {role.isActive ? "Active" : "Inactive"} · {role._count.users}{" "}
              staff · {role.permissions.length} permissions
            </p>
            {role.isSystem ? (
              <p className="mt-2 text-sm font-medium">
                System role — read only
              </p>
            ) : null}
          </li>
        ))}
      </ul>
    </main>
  );
}
