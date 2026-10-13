import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

import { authenticateCredentials } from "../application/authenticate-credentials";
import { prisma } from "../infrastructure/prisma";

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  session: {
    strategy: "jwt",
    maxAge: 12 * 60 * 60,
  },
  jwt: {
    maxAge: 12 * 60 * 60,
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "Lumina staff credentials",
      credentials: {
        identifier: { label: "Username or email", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, request) {
        return authenticateCredentials({
          prisma,
          identifier: credentials?.identifier,
          password: credentials?.password,
          headers: request.headers ?? {},
        });
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user, trigger }) {
      if (user) {
        token.sub = user.id;
        token.displayName = user.displayName;
        token.sessionId = user.sessionId;
        token.sessionBinding = user.sessionBinding;
        token.authzVersion = user.authzVersion;
        token.signedInAt = user.signedInAt;
        token.absoluteExpiresAt = user.absoluteExpiresAt;
      }
      // Client-triggered session updates are never allowed to change identity
      // or authorization claims.
      if (trigger === "update") return token;
      return token;
    },
    async session({ session, token }) {
      session.user = {
        id: typeof token.sub === "string" ? token.sub : "",
        displayName:
          typeof token.displayName === "string" ? token.displayName : "",
      };
      if (typeof token.absoluteExpiresAt === "number") {
        session.expires = new Date(token.absoluteExpiresAt).toISOString();
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      return safeRedirect(url, baseUrl);
    },
  },
  logger: {
    error(code) {
      console.error("Authentication error", { code });
    },
    warn(code) {
      console.warn("Authentication warning", { code });
    },
  },
  debug: false,
};

export function safeRedirect(url: string, baseUrl: string): string {
  try {
    const base = new URL(baseUrl);
    if (url.startsWith("/") && !url.startsWith("//")) {
      const destination = new URL(url, base);
      return isSafeDestination(destination, base)
        ? destination.toString()
        : baseUrl;
    }
    const destination = new URL(url);
    return isSafeDestination(destination, base)
      ? destination.toString()
      : baseUrl;
  } catch {
    return baseUrl;
  }
}

function isSafeDestination(destination: URL, base: URL): boolean {
  return (
    destination.origin === base.origin &&
    !destination.username &&
    !destination.password &&
    !destination.pathname.startsWith("/api/auth/")
  );
}
