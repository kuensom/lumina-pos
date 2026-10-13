import { describe, expect, it } from "vitest";

import {
  MAX_AUTH_REQUEST_BODY_BYTES,
  readBoundedAuthBody,
} from "./bounded-auth-request";

describe("authentication request body bounds", () => {
  it("accepts a body at the limit", async () => {
    const body = "a".repeat(MAX_AUTH_REQUEST_BODY_BYTES);
    const request = new Request("https://pos.example.test/api/auth/callback", {
      method: "POST",
      body,
    });
    await expect(readBoundedAuthBody(request)).resolves.toHaveLength(
      MAX_AUTH_REQUEST_BODY_BYTES,
    );
  });

  it("rejects declared and streamed bodies over the limit", async () => {
    const declared = new Request("https://pos.example.test/api/auth/callback", {
      method: "POST",
      headers: {
        "content-length": String(MAX_AUTH_REQUEST_BODY_BYTES + 1),
      },
      body: "small",
    });
    await expect(readBoundedAuthBody(declared)).resolves.toBeNull();

    const streamed = new Request("https://pos.example.test/api/auth/callback", {
      method: "POST",
      body: "a".repeat(MAX_AUTH_REQUEST_BODY_BYTES + 1),
    });
    streamed.headers.delete("content-length");
    await expect(readBoundedAuthBody(streamed)).resolves.toBeNull();
  });
});
