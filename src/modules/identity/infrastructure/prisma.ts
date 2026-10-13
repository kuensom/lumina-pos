import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  luminaPrisma?: PrismaClient;
};

export const prisma = globalForPrisma.luminaPrisma ?? new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.luminaPrisma = prisma;
}
