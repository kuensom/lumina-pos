"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { GENERIC_LOGIN_FAILURE } from "../application/authentication-types";

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    try {
      const result = await signIn("credentials", {
        identifier: data.get("identifier"),
        password: data.get("password"),
        callbackUrl: "/",
        redirect: false,
      });
      if (!result?.ok) {
        setError(GENERIC_LOGIN_FAILURE);
        return;
      }
      router.replace("/");
      router.refresh();
    } catch {
      setError(GENERIC_LOGIN_FAILURE);
    } finally {
      setPending(false);
    }
  }

  return (
    <form className="mt-7 space-y-5" onSubmit={submit}>
      {error ? (
        <p
          role="alert"
          className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-900"
        >
          {error}
        </p>
      ) : null}
      <div>
        <label htmlFor="identifier" className="block text-sm font-medium">
          Username or email
        </label>
        <input
          id="identifier"
          name="identifier"
          type="text"
          autoComplete="username"
          required
          maxLength={320}
          disabled={pending}
          className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-3 py-2"
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
          required
          minLength={12}
          maxLength={128}
          disabled={pending}
          className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-3 py-2"
        />
      </div>
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded-lg bg-forest px-4 py-3 font-semibold text-white disabled:bg-slate-400"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
