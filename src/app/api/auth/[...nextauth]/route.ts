import NextAuth from "next-auth";
import { NextRequest, NextResponse } from "next/server";

import { authOptions } from "@/modules/identity/auth/auth-options";
import { readBoundedAuthBody } from "@/modules/identity/security/bounded-auth-request";

const handler = NextAuth(authOptions);

export { handler as GET };

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ nextauth: string[] }> },
) {
  const body = await readBoundedAuthBody(request);
  if (!body) {
    return NextResponse.json(
      { error: "Authentication request rejected." },
      { status: 413 },
    );
  }
  const boundedRequest = new NextRequest(request.url, {
    method: request.method,
    headers: request.headers,
    body: new TextDecoder().decode(body),
  });
  return handler(boundedRequest, context);
}
