"use client";

import { useActionState, useCallback, useEffect, useState } from "react";

import type { CredentialActionState } from "../server/credential-actions";

const initialState: CredentialActionState = { ok: false, message: "" };

export function CredentialForm({
  action,
  children,
  submitLabel,
}: {
  action: (
    state: CredentialActionState,
    data: FormData,
  ) => Promise<CredentialActionState>;
  children: React.ReactNode;
  submitLabel: string;
}) {
  const [instance, setInstance] = useState(0);
  const disposeSecret = useCallback(
    () => setInstance((value) => value + 1),
    [],
  );
  return (
    <CredentialFormInstance
      key={instance}
      action={action}
      submitLabel={submitLabel}
      disposeSecret={disposeSecret}
    >
      {children}
    </CredentialFormInstance>
  );
}

function CredentialFormInstance({
  action,
  children,
  submitLabel,
  disposeSecret,
}: {
  action: (
    state: CredentialActionState,
    data: FormData,
  ) => Promise<CredentialActionState>;
  children: React.ReactNode;
  submitLabel: string;
  disposeSecret: () => void;
}) {
  const [state, formAction, pending] = useActionState(action, initialState);
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    if (!state.voucher) return;
    window.addEventListener("pagehide", disposeSecret, { once: true });
    return () => window.removeEventListener("pagehide", disposeSecret);
  }, [disposeSecret, state.voucher]);

  return (
    <form action={formAction} className="space-y-4" autoComplete="off">
      {state.message ? (
        <p
          role={state.ok ? "status" : "alert"}
          className="rounded-lg border p-3"
        >
          {state.message}
        </p>
      ) : null}
      {state.voucher ? (
        <div className="rounded-lg border border-amber-400 bg-amber-50 p-4">
          {revealed ? (
            <>
              <code
                className="block break-all text-lg"
                data-testid="one-time-voucher"
              >
                {state.voucher}
              </code>
              <button
                type="button"
                onClick={disposeSecret}
                className="mt-3 rounded bg-forest px-3 py-2 text-white"
              >
                Handover complete — dismiss permanently
              </button>
            </>
          ) : (
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setRevealed(true)}
                className="rounded bg-forest px-3 py-2 text-white"
              >
                Reveal voucher once
              </button>
              <button
                type="button"
                onClick={disposeSecret}
                className="rounded border px-3 py-2"
              >
                Dismiss without revealing
              </button>
            </div>
          )}
          <p className="mt-2 text-sm">
            Printing is disabled. Confirm staff identity and let the staff
            member retain custody. The application cannot prevent someone who
            sees the voucher from recording it outside the system.
          </p>
        </div>
      ) : null}
      {children}
      <button
        disabled={pending || Boolean(state.voucher)}
        className="rounded-lg bg-forest px-4 py-2 font-semibold text-white disabled:bg-slate-400"
      >
        {pending ? "Working…" : submitLabel}
      </button>
    </form>
  );
}
