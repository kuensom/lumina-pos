import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface User {
    displayName: string;
    sessionId: string;
    sessionBinding: string;
    authzVersion: number;
    passwordVersion: number;
    signedInAt: number;
    absoluteExpiresAt: number;
  }

  interface Session {
    user: {
      id: string;
      displayName: string;
    } & Omit<DefaultSession["user"], "name" | "email" | "image">;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    displayName?: string;
    sessionId?: string;
    sessionBinding?: string;
    authzVersion?: number;
    passwordVersion?: number;
    signedInAt?: number;
    absoluteExpiresAt?: number;
  }
}
