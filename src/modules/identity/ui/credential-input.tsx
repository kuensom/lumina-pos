"use client";

import { useEffect, useState } from "react";

export function CredentialInput() {
  const [credential, setCredential] = useState("");
  useEffect(() => {
    const value = new URLSearchParams(window.location.hash.slice(1)).get(
      "token",
    );
    if (value) {
      setCredential(value.slice(0, 96));
      history.replaceState(null, "", window.location.pathname);
    }
  }, []);
  return (
    <label className="block">
      <span>One-time credential</span>
      <input
        name="credential"
        value={credential}
        onChange={(event) => setCredential(event.target.value)}
        required
        maxLength={96}
        className="mt-1 w-full rounded border p-2"
      />
    </label>
  );
}
