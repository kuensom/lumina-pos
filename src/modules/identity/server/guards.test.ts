import type { PrismaClient } from "@prisma/client";
import { describe, expect, it } from "vitest";

import { authenticateRequest } from "./guards";

describe("server authentication failure mode", () => {
  it("fails closed when PostgreSQL is unavailable", async () => {
    const unavailable = {
      $transaction: async () => {
        throw new Error("database unavailable");
      },
    } as unknown as PrismaClient;

    await expect(
      authenticateRequest({ prisma: unavailable, claims: {} }),
    ).rejects.toThrow("database unavailable");
  });
});
