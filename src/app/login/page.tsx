import { LoginForm } from "@/modules/identity/ui/login-form";

export default function LoginPage() {
  return (
    <main className="mx-auto flex w-full max-w-lg flex-1 items-center px-5 py-12">
      <section
        aria-labelledby="login-title"
        className="w-full rounded-2xl bg-white p-8 shadow-sm"
      >
        <p className="text-sm font-semibold uppercase tracking-[0.18em] text-forest">
          Staff access
        </p>
        <h1 id="login-title" className="mt-2 text-3xl font-bold">
          Sign in to Lumina POS
        </h1>
        <p className="mt-4 text-sm leading-6 text-slate-700">
          Enter your username or optional email address and password.
        </p>
        <LoginForm />
        <p id="login-note" className="mt-4 text-sm text-slate-600">
          Password recovery is administrator-assisted and is not available from
          this screen.
        </p>
      </section>
    </main>
  );
}
