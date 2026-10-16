import { isIP } from "node:net";

export type HeaderSource =
  | Headers
  | Record<string, string | string[] | undefined>;

const TRUSTED_CLIENT_IP_HEADER = "x-lumina-client-ip";

export function trustedNetworkIdentifier(headers: HeaderSource): string | null {
  if (process.env.TRUST_PROXY_HEADERS !== "true") {
    // NextAuth does not expose the peer socket address. Without a reviewed
    // reverse-proxy boundary, omit network limiting rather than trust a
    // spoofable header or collapse every shop client into one shared bucket.
    return null;
  }

  const clientIp = headerValue(headers, TRUSTED_CLIENT_IP_HEADER)?.trim();
  if (!clientIp || clientIp.includes(",") || isIP(clientIp) === 0) return null;
  return clientIp;
}

export function userAgentSummary(headers: HeaderSource): string | null {
  const value = headerValue(headers, "user-agent")?.trim();
  return value ? value.slice(0, 250) : null;
}

export function assertSameOrigin(headers: Headers): void {
  const origin = headers.get("origin");
  const configured = process.env.NEXTAUTH_URL;
  if (!origin || origin === "null" || !configured) {
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
