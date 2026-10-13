"use client";

import { useActionState, type ReactNode } from "react";

import type { AdministrationActionState } from "../server/administration-actions";

const initialState: AdministrationActionState = { ok: false, message: "" };

export function AdministrationForm({
  action,
  children,
  submitLabel,
  pendingLabel = "Saving…",
  className = "space-y-4",
}: {
  action: (
    state: AdministrationActionState,
    data: FormData,
  ) => Promise<AdministrationActionState>;
  children: ReactNode;
  submitLabel: string;
  pendingLabel?: string;
  className?: string;
}) {
  const [state, formAction, pending] = useActionState(action, initialState);
  return (
    <form action={formAction} className={className}>
      {state.message ? (
        <p
          role={state.ok ? "status" : "alert"}
          tabIndex={-1}
          className={`rounded-lg border p-3 text-sm ${
            state.ok
              ? "border-emerald-300 bg-emerald-50 text-emerald-950"
              : "border-red-300 bg-red-50 text-red-950"
          }`}
        >
          {state.message}
        </p>
      ) : null}
      {children}
      <button
        type="submit"
        disabled={pending}
        className="rounded-lg bg-forest px-4 py-2 font-semibold text-white disabled:bg-slate-400"
      >
        {pending ? pendingLabel : submitLabel}
      </button>
    </form>
  );
}
