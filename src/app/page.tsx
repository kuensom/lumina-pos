const plannedAreas = ["Products", "Inventory", "Retail", "Receipts", "Reports"];

export default function HomePage() {
  return (
    <main className="mx-auto w-full max-w-6xl px-5 py-10 sm:px-8">
      <section aria-labelledby="dashboard-title" className="space-y-4">
        <p className="text-sm font-semibold uppercase tracking-[0.18em] text-forest">
          Foundation preview
        </p>
        <h1
          id="dashboard-title"
          className="text-4xl font-bold tracking-tight sm:text-5xl"
        >
          Lumina POS dashboard
        </h1>
        <p className="max-w-2xl text-lg leading-8 text-slate-700">
          This placeholder confirms that the application shell is running.
          Operational POS features are not implemented in this foundation
          ticket.
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
                Not available in LUM-001.
              </p>
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}
