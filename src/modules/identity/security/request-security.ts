import { isIP } from "node:net";

export type HeaderSource =
  | Headers
  | Record<string, string | string[] | undefined>;

export function trustedNetworkIdentifier(headers: HeaderSource): string {
  if (process.env.TRUST_PROXY_HEADERS !== "true") {
    return "direct-client";
  }

  const forwarded = headerValue(headers, "x-forwarded-for")
    ?.split(",")[0]
    ?.trim();
  if (!forwarded || isIP(forwarded) === 0) {
    return "invalid-forwarded-client";
  }
  return forwarded;
}

export function userAgentSummary(headers: HeaderSource): string | null {
  const value = headerValue(headers, "user-agent")?.trim();
  return value ? value.slice(0, 250) : null;
}

export function assertSameOrigin(headers: Headers): void {
  const origin = headers.get("origin");
  const configured = process.env.NEXTAUTH_URL;
  if (!origin || !configured) {
    throw new Error("A canonical origin is required for this request.");
  }
  if (new URL(origin).origin !== new URL(configured).origin) {
    throw new Error("Cross-origin request rejected.");
  }
}

function headerValue(headers: HeaderSource, name: string): string | undefined {
  if (headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}
