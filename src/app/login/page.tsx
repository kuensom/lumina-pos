export default function LoginPage() {
  return (
    <main className="mx-auto flex w-full max-w-lg flex-1 items-center px-5 py-12">
      <section
        aria-labelledby="login-title"
        className="w-full rounded-2xl bg-white p-8 shadow-sm"
      >
        <p className="text-sm font-semibold uppercase tracking-[0.18em] text-forest">
          Placeholder
        </p>
        <h1 id="login-title" className="mt-2 text-3xl font-bold">
          Sign in to Lumina POS
        </h1>
        <div
          role="status"
          className="mt-5 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm"
        >
          Authentication is not implemented. This form is a nonfunctional
          interface preview.
        </div>
        <form className="mt-7 space-y-5" aria-describedby="login-note">
          <div>
            <label htmlFor="email" className="block text-sm font-medium">
              Email
            </label>
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              disabled
              className="mt-2 w-full rounded-lg border border-slate-300 bg-slate-100 px-3 py-2"
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm font-medium">
              Password
            </label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              disabled
              className="mt-2 w-full rounded-lg border border-slate-300 bg-slate-100 px-3 py-2"
            />
          </div>
          <button
            type="button"
            disabled
            className="w-full rounded-lg bg-slate-400 px-4 py-3 font-semibold text-white"
          >
            Sign in unavailable
          </button>
        </form>
        <p id="login-note" className="mt-4 text-sm text-slate-600">
          Functional authentication and role permissions belong to LUM-002.
        </p>
      </section>
    </main>
  );
}
