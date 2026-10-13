import { describe, expect, it } from "vitest";

import { clientVisibleSession, safeRedirect } from "./auth-options";

describe("safe authentication redirects", () => {
  const base = "https://pos.example.test";

  it("allows local application destinations", () => {
    expect(safeRedirect("/", base)).toBe("https://pos.example.test/");
    expect(safeRedirect(`${base}/reports`, base)).toBe(`${base}/reports`);
  });

  it.each([
    "https://evil.example/steal",
    "//evil.example/steal",
    "javascript:alert(1)",
    "https://user:password@pos.example.test/",
    "/api/auth/signout",
  ])("rejects unsafe destination %s", (destination) => {
    expect(safeRedirect(destination, base)).toBe(base);
  });
});

describe("client-visible session projection", () => {
  it("never exposes JWT binding or authorization claims", () => {
    const session = clientVisibleSession(
      {
        user: { id: "", displayName: "" },
        expires: new Date(0).toISOString(),
      },
      {
        sub: "user-id",
        displayName: "Staff member",
        sessionId: "database-session-id",
        sessionBinding: "opaque-cookie-secret",
        authzVersion: 42,
        signedInAt: 1,
        absoluteExpiresAt: 2,
      },
    );
    expect(session).toEqual({
      user: { id: "user-id", displayName: "Staff member" },
      expires: new Date(2).toISOString(),
    });
    expect(JSON.stringify(session)).not.toContain("opaque-cookie-secret");
    expect(JSON.stringify(session)).not.toContain("database-session-id");
  });
});
