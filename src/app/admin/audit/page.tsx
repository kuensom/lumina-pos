import { listAdministrationAudit } from "@/modules/identity/application/administration-service";
import { prisma } from "@/modules/identity/infrastructure/prisma";
import {
  administrationPageClaims,
  handleAdministrationPageError,
} from "@/modules/identity/server/administration-page";

export default async function AdministrationAuditPage() {
  const claims = await administrationPageClaims();
  let events;
  try {
    events = await listAdministrationAudit({ prisma, claims });
  } catch (error) {
    handleAdministrationPageError(error);
  }
  return (
    <main className="mx-auto w-full max-w-5xl px-5 py-10 sm:px-8">
      <p className="text-sm font-semibold uppercase tracking-wider text-forest">
        Administration
      </p>
      <h1 className="text-3xl font-bold">Identity audit events</h1>
      <div className="mt-6 overflow-x-auto rounded-xl bg-white shadow-sm">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b">
              <th className="p-3">Time</th>
              <th className="p-3">Event</th>
              <th className="p-3">Outcome</th>
              <th className="p-3">Target</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-b last:border-0">
                <td className="p-3">
                  <time dateTime={event.createdAt.toISOString()}>
                    {event.createdAt.toLocaleString("en-BT")}
                  </time>
                </td>
                <td className="p-3">{event.eventType}</td>
                <td className="p-3">{event.outcome}</td>
                <td className="p-3">
                  {event.targetType ?? "—"}
                  {event.targetId ? ` (${event.targetId})` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
