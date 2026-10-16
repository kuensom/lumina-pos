import { PrismaClient } from "@prisma/client";
import { validateIdentitySet } from "./database-identity-policy.mjs";

const primaryUrl = requiredUrl("MIGRATION_DATABASE_URL");
const shadowUrl = requiredUrl("SHADOW_DATABASE_URL");
const runtimeUrl = requiredUrl("DATABASE_URL");
const operation = process.env.DATABASE_OPERATION ?? "inspect";
const context = process.env.DATABASE_SAFETY_CONTEXT ?? "local";

const primary = await identity(primaryUrl);
const shadow = await identity(shadowUrl);
const runtime = await identity(runtimeUrl);
const rollbackUrl =
  operation === "rollback" ? requiredUrl("ROLLBACK_DATABASE_URL") : null;
const rollback = rollbackUrl ? await identity(rollbackUrl) : undefined;

validateIdentitySet({ primary, runtime, shadow, rollback, context, operation });

console.log(
  `Database identities verified: ${primary.database} (${primary.user}), ${runtime.database} (${runtime.user}), shadow ${shadow.database} (${shadow.user}).`,
);

async function identity(url) {
  const client = new PrismaClient({ datasourceUrl: url.toString() });
  try {
    const [row] = await client.$queryRaw`
      SELECT current_database() AS database,
             current_user AS "user",
             COALESCE(inet_server_addr()::text, 'local') AS host,
             inet_server_port() AS port
    `;
    return { ...row, connectionHost: url.hostname };
  } finally {
    await client.$disconnect();
  }
}

function requiredUrl(name) {
  const value = process.env[name];
  if (!value)
    throw new Error(`${name} is required; refusing database operation.`);
  const url = new URL(value);
  if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") {
    throw new Error(`${name} must be a PostgreSQL URL.`);
  }
  return url;
}
