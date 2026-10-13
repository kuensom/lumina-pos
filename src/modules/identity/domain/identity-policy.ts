import { z } from "zod";

const reservedUsernames = new Set([
  "admin",
  "administrator",
  "api",
  "auth",
  "login",
  "logout",
  "null",
  "root",
  "security",
  "super-admin",
  "superadmin",
  "support",
  "system",
  "undefined",
]);

const usernameSchema = z
  .string()
  .regex(
    /^[a-z0-9._-]{3,32}$/,
    "Username must be 3–32 lowercase ASCII characters.",
  )
  .refine(
    (username) => !reservedUsernames.has(username),
    "Username is reserved.",
  );

const emailSchema = z.string().email().max(320);

export const PASSWORD_MIN_CHARACTERS = 12;
export const PASSWORD_MAX_CHARACTERS = 128;

export function normalizeUsername(input: string): string {
  const normalized = input.trim().toLowerCase();
  return usernameSchema.parse(normalized);
}

export function normalizeOptionalEmail(
  input: string | null | undefined,
): string | null {
  const trimmed = input?.trim();
  if (!trimmed) {
    return null;
  }

  return emailSchema.parse(trimmed.toLowerCase());
}

export function assertPasswordPolicy(password: string): void {
  const characterCount = Array.from(password).length;
  if (
    characterCount < PASSWORD_MIN_CHARACTERS ||
    characterCount > PASSWORD_MAX_CHARACTERS
  ) {
    throw new Error(
      `Password must contain between ${PASSWORD_MIN_CHARACTERS} and ${PASSWORD_MAX_CHARACTERS} characters.`,
    );
  }
}

export function isReservedUsername(username: string): boolean {
  return reservedUsernames.has(username.toLowerCase());
}
