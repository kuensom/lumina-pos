import { Prisma } from "@prisma/client";

export async function retrySerializableTransaction<T>(
  operation: () => Promise<T>,
  maximumAttempts = 3,
): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      if (attempt >= maximumAttempts || !isSerializationConflict(error)) {
        throw error;
      }
    }
  }
}

function isSerializationConflict(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code === "P2034") return true;
  return (
    error.code === "P2010" &&
    typeof error.meta?.code === "string" &&
    error.meta.code === "40001"
  );
}
