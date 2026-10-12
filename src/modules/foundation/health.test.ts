import { describe, expect, it } from "vitest";

import { healthPayload } from "./health";

describe("healthPayload", () => {
  it("reports a stable healthy service response", () => {
    expect(healthPayload()).toEqual({ status: "ok", service: "lumina-pos" });
  });
});
