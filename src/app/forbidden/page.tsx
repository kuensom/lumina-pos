import Link from "next/link";

export default function ForbiddenPage() {
  return (
    <main className="mx-auto w-full max-w-xl px-5 py-16 text-center">
      <h1 className="text-3xl font-bold">Access denied</h1>
      <p className="mt-4 text-slate-700">
        Your account does not currently have permission to view that resource.
      </p>
      <Link href="/" className="mt-6 inline-block font-semibold text-forest">
        Return to the dashboard
      </Link>
    </main>
  );
}
