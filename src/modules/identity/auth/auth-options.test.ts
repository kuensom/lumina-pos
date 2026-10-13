import { describe, expect, it } from "vitest";

import { safeRedirect } from "./auth-options";

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
