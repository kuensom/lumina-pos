export type CreatedAuthenticationSession = {
  id: string;
  sub: string;
  displayName: string;
  sessionId: string;
  sessionBinding: string;
  authzVersion: number;
  passwordVersion: number;
  signedInAt: number;
  absoluteExpiresAt: number;
};

export const GENERIC_LOGIN_FAILURE =
  "Unable to sign in with those credentials.";
