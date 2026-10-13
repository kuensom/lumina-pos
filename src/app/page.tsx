import { redirect } from "next/navigation";

import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  AuthenticationRequiredError,
  PermissionDeniedError,
  requirePermission,
} from "@/modules/identity/server/guards";
import { claimsFromCurrentCookies } from "@/modules/identity/server/session-token";
import { LogoutButton } from "@/modules/identity/ui/logout";

const plannedAreas = ["Products", "Inventory", "Retail", "Receipts", "Reports"];

export default async function HomePage() {
  const claims = await claimsFromCurrentCookies();
  if (!claims) redirect("/login");
  let principal;
  try {
    principal = await requirePermission({
      prisma,
      claims,
      permission: "dashboard:view",
      refreshActivity: true,
    });
  } catch (error) {
    if (error instanceof AuthenticationRequiredError) redirect("/login");
    if (error instanceof PermissionDeniedError) redirect("/forbidden");
    throw error;
  }

  return (
    <main className="mx-auto w-full max-w-6xl px-5 py-10 sm:px-8">
      <section aria-labelledby="dashboard-title" className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-forest">
            Authenticated workspace
          </p>
          <LogoutButton />
        </div>
        <h1
          id="dashboard-title"
          className="text-4xl font-bold tracking-tight sm:text-5xl"
        >
          Lumina POS dashboard
        </h1>
        <p className="max-w-2xl text-lg leading-8 text-slate-700">
          Welcome, {principal.displayName}. Your session and dashboard
          permission were verified on the server.
        </p>
      </section>

      <section aria-labelledby="planned-title" className="mt-12">
        <h2 id="planned-title" className="text-xl font-semibold">
          Planned application areas
        </h2>
        <ul className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {plannedAreas.map((area) => (
            <li
              key={area}
              className="rounded-xl border border-slate-300 bg-white p-5 shadow-sm"
            >
              <span className="font-semibold">{area}</span>
              <p className="mt-2 text-sm text-slate-600">
                Not available in LUM-002-B2.
              </p>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
