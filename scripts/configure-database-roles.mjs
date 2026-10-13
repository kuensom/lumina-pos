import { PrismaClient } from "@prisma/client";

const phase = process.argv[2];
if (phase !== "create" && phase !== "grant") {
  throw new Error(
    "Usage: node scripts/configure-database-roles.mjs <create|grant>",
  );
}

const requiredEnvironment = [
  "DATABASE_ADMIN_URL",
  "MIGRATION_DATABASE_USER",
  "MIGRATION_DATABASE_PASSWORD",
  "RUNTIME_DATABASE_USER",
  "RUNTIME_DATABASE_PASSWORD",
];

for (const name of requiredEnvironment) {
  if (!process.env[name]) {
    throw new Error(`${name} is required.`);
  }
}

const adminUrl = process.env.DATABASE_ADMIN_URL;
const migrationUser = validateRoleName(process.env.MIGRATION_DATABASE_USER);
const runtimeUser = validateRoleName(process.env.RUNTIME_DATABASE_USER);
const migrationPassword = validatePassword(
  process.env.MIGRATION_DATABASE_PASSWORD,
);
const runtimePassword = validatePassword(process.env.RUNTIME_DATABASE_PASSWORD);
const databaseName = new URL(adminUrl).pathname.slice(1);
if (!databaseName) {
  throw new Error("DATABASE_ADMIN_URL must select a database.");
}

const database = new PrismaClient({ datasourceUrl: adminUrl });

try {
  if (phase === "create") {
    await createOrRotateLogin(migrationUser, migrationPassword);
    await createOrRotateLogin(runtimeUser, runtimePassword);

    await execute(`REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
    await execute(
      `REVOKE TEMPORARY ON DATABASE ${identifier(databaseName)} FROM PUBLIC`,
    );
    await execute(
      `GRANT CONNECT ON DATABASE ${identifier(databaseName)} TO ${identifier(migrationUser)}, ${identifier(runtimeUser)}`,
    );
    await execute(
      `GRANT USAGE, CREATE ON SCHEMA public TO ${identifier(migrationUser)}`,
    );
    await execute(`GRANT USAGE ON SCHEMA public TO ${identifier(runtimeUser)}`);
  } else {
    await configureRuntimePrivileges();
  }
} finally {
  await database.$disconnect();
}

async function createOrRotateLogin(roleName, password) {
  const existing = await database.$queryRawUnsafe(
    "SELECT 1 FROM pg_roles WHERE rolname = $1",
    roleName,
  );
  if (existing.length === 0) {
    await execute(
      `CREATE ROLE ${identifier(roleName)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`,
    );
  }
  await execute(
    `ALTER ROLE ${identifier(roleName)} PASSWORD ${literal(password)}`,
  );
}

async function configureRuntimePrivileges() {
  const runtime = identifier(runtimeUser);
  const migration = identifier(migrationUser);

  await execute(
    `REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ${runtime}`,
  );
  await execute(
    `REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, ${runtime}`,
  );

  await execute(`GRANT SELECT, INSERT, UPDATE ON TABLE users TO ${runtime}`);
  // Prisma supplies schema defaults in role INSERT statements, so the trigger
  // is the authoritative guard against runtime system-role creation.
  await execute(`GRANT SELECT, INSERT ON TABLE roles TO ${runtime}`);
  await execute(
    `GRANT UPDATE (name, description, is_active, updated_at) ON TABLE roles TO ${runtime}`,
  );
  await execute(`GRANT SELECT ON TABLE permissions TO ${runtime}`);
  await execute(
    `GRANT SELECT, INSERT, DELETE ON TABLE user_roles TO ${runtime}`,
  );
  await execute(
    `GRANT SELECT, INSERT, DELETE ON TABLE role_permissions TO ${runtime}`,
  );
  await execute(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE sessions TO ${runtime}`,
  );
  await execute(
    `GRANT SELECT, INSERT, UPDATE ON TABLE password_reset_grants TO ${runtime}`,
  );
  await execute(`GRANT SELECT, INSERT ON TABLE audit_events TO ${runtime}`);
  await execute(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE auth_rate_limit_buckets TO ${runtime}`,
  );
  // This function only acquires the transaction-scoped advisory lock shared by
  // the B3 service and invariant triggers; runtime cannot bypass the invariant.
  await execute(
    `GRANT EXECUTE ON FUNCTION lock_super_administrator_invariant() TO ${runtime}`,
  );

  await execute(
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC`,
  );
  await execute(
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migration} IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC`,
  );
}

async function execute(statement) {
  await database.$executeRawUnsafe(statement);
}

function validateRoleName(value) {
  if (!/^[a-z][a-z0-9_]{2,62}$/.test(value)) {
    throw new Error(
      "Database role names must be lowercase PostgreSQL identifiers.",
    );
  }
  return value;
}

function validatePassword(value) {
  if (value.length < 16 || value.length > 256 || /[\r\n\0]/.test(value)) {
    throw new Error(
      "Database passwords must contain 16–256 characters without control newlines.",
    );
  }
  return value;
}

function identifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function literal(value) {
  return `'${value.replaceAll("'", "''")}'`;
}
