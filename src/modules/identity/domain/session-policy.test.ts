import { describe, expect, it } from "vitest";

import { rateLimitWindowStart, sessionExpiryFrom } from "./session-policy";

describe("session policy", () => {
  it("sets a 60-minute idle and immutable 12-hour absolute boundary", () => {
    const now = new Date("2026-10-13T00:00:00.000Z");
    const expiry = sessionExpiryFrom(now);
    expect(expiry.idleExpiresAt.toISOString()).toBe("2026-10-13T01:00:00.000Z");
    expect(expiry.absoluteExpiresAt.toISOString()).toBe(
      "2026-10-13T12:00:00.000Z",
    );
  });

  it("uses deterministic UTC 15-minute rate windows", () => {
    expect(
      rateLimitWindowStart(new Date("2026-10-13T00:29:59.999Z")).toISOString(),
    ).toBe("2026-10-13T00:15:00.000Z");
  });
});
