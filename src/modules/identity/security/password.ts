import { hash, parseOptions, verify, type Options } from "@node-rs/argon2";

import { assertPasswordPolicy } from "../domain/identity-policy";

export const ARGON2_POLICY = Object.freeze({
  // Numeric values avoid importing the package's ambient const enums, which
  // are incompatible with this project's isolatedModules setting.
  algorithm: 2,
  version: 1,
  memoryCost: 65_536,
  timeCost: 3,
  parallelism: 1,
  outputLen: 32,
} satisfies Options);

export async function hashPassword(password: string): Promise<string> {
  assertPasswordPolicy(password);
  return hash(password, ARGON2_POLICY);
}

export async function verifyPassword(
  passwordHash: string,
  password: string,
): Promise<boolean> {
  try {
    return await verify(passwordHash, password);
  } catch {
    return false;
  }
}

export function passwordHashNeedsRehash(passwordHash: string): boolean {
  try {
    const parsed = parseOptions(passwordHash);
    return (
      parsed.algorithm !== ARGON2_POLICY.algorithm ||
      parsed.version !== ARGON2_POLICY.version ||
      parsed.memoryCost !== ARGON2_POLICY.memoryCost ||
      parsed.timeCost !== ARGON2_POLICY.timeCost ||
      parsed.parallelism !== ARGON2_POLICY.parallelism ||
      parsed.outputLen !== ARGON2_POLICY.outputLen
    );
  } catch {
    return true;
  }
}
