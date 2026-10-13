import Link from "next/link";

import { listStaff } from "@/modules/identity/application/administration-service";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";

export default async function StaffDirectoryPage({
  searchParams,
}: {
  searchParams: Promise<{ query?: string; status?: string; cursor?: string }>;
}) {
  const claims = await administrationPageClaims();
  const params = await searchParams;
  let result;
  try {
    result = await listStaff({ prisma, claims, search: params });
  } catch (error) {
    handleAdministrationPageError(error);
  }

  return (
    <main className="mx-auto w-full max-w-6xl px-5 py-10 sm:px-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm font-semibold uppercase tracking-wider text-forest">
            Administration
          </p>
          <h1 className="text-3xl font-bold">Staff directory</h1>
        </div>
        {result.viewer !== "supervisor" ? (
          <Link
            className="rounded-lg bg-forest px-4 py-2 text-white"
            href="/admin/staff/new"
          >
            Create staff account
          </Link>
        ) : null}
      </div>
      <form className="mt-6 grid gap-3 rounded-xl bg-white p-4 shadow-sm sm:grid-cols-[1fr_auto_auto]">
        <label>
          <span className="block text-sm font-medium">Search staff</span>
          <input
            name="query"
            defaultValue={params.query}
            maxLength={100}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
          />
        </label>
        <label>
          <span className="block text-sm font-medium">Status</span>
          <select
            name="status"
            defaultValue={params.status ?? ""}
            className="mt-1 rounded-lg border border-slate-300 px-3 py-2"
          >
            <option value="">All statuses</option>
            <option value="PENDING_PASSWORD">Pending password</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
            <option value="LOCKED">Locked</option>
          </select>
        </label>
        <button className="self-end rounded-lg border border-forest px-4 py-2 font-semibold">
          Search
        </button>
      </form>
      <div className="mt-6 overflow-x-auto rounded-xl bg-white shadow-sm">
        <table className="w-full border-collapse text-left">
          <caption className="sr-only">
            Authorised staff directory results
          </caption>
          <thead className="border-b bg-slate-50 text-sm">
            <tr>
              <th className="p-3">Staff member</th>
              <th className="p-3">Status</th>
              <th className="p-3">Roles</th>
              {result.viewer !== "supervisor" ? (
                <th className="p-3">Email</th>
              ) : null}
            </tr>
          </thead>
          <tbody>
            {result.staff.map((staff) => (
              <tr key={staff.id} className="border-b last:border-0">
                <td className="p-3">
                  <Link
                    className="font-semibold text-forest underline"
                    href={`/admin/staff/${staff.id}`}
                  >
                    {staff.displayName}
                  </Link>
                  <div className="text-sm text-slate-600">{staff.username}</div>
                </td>
                <td className="p-3">{staff.status.replaceAll("_", " ")}</td>
                <td className="p-3">
                  {staff.roles.map(({ role }) => role.name).join(", ") ||
                    "No roles"}
                </td>
                {result.viewer !== "supervisor" ? (
                  <td className="p-3">
                    {"email" in staff ? (staff.email ?? "—") : "—"}
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {result.nextCursor ? (
        <Link
          className="mt-5 inline-block underline"
          href={`/admin/staff?query=${encodeURIComponent(params.query ?? "")}&status=${encodeURIComponent(params.status ?? "")}&cursor=${result.nextCursor}`}
        >
          Next page
        </Link>
      ) : null}
    </main>
  );
}
