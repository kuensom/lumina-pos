import { afterEach, describe, expect, it } from "vitest";

import { trustedNetworkIdentifier } from "./request-security";

const originalTrustSetting = process.env.TRUST_PROXY_HEADERS;

afterEach(() => {
  if (originalTrustSetting === undefined) {
    delete process.env.TRUST_PROXY_HEADERS;
  } else {
    process.env.TRUST_PROXY_HEADERS = originalTrustSetting;
  }
});

describe("trusted client network boundary", () => {
  it("ignores spoofable forwarding and proxy headers when trust is disabled", () => {
    process.env.TRUST_PROXY_HEADERS = "false";
    expect(
      trustedNetworkIdentifier(
        new Headers({
          "x-forwarded-for": "203.0.113.1",
          "x-real-ip": "203.0.113.2",
          "x-lumina-client-ip": "203.0.113.3",
        }),
      ),
    ).toBeNull();
  });

  it("accepts only one valid proxy-owned address at the trusted boundary", () => {
    process.env.TRUST_PROXY_HEADERS = "true";
    expect(
      trustedNetworkIdentifier(
        new Headers({
          "x-forwarded-for": "198.51.100.99",
          "x-lumina-client-ip": "203.0.113.10",
        }),
      ),
    ).toBe("203.0.113.10");
    expect(
      trustedNetworkIdentifier(
        new Headers({ "x-lumina-client-ip": "203.0.113.10, 10.0.0.1" }),
      ),
    ).toBeNull();
    expect(
      trustedNetworkIdentifier(
        new Headers({ "x-lumina-client-ip": "not-an-address" }),
      ),
    ).toBeNull();
  });

  it("keeps independently established clients distinct", () => {
    process.env.TRUST_PROXY_HEADERS = "true";
    const first = trustedNetworkIdentifier(
      new Headers({ "x-lumina-client-ip": "192.0.2.10" }),
    );
    const second = trustedNetworkIdentifier(
      new Headers({ "x-lumina-client-ip": "192.0.2.11" }),
    );
    expect(first).not.toBe(second);
  });
});
