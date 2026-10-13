import { randomUUID } from "node:crypto";

import { PrismaClient } from "@prisma/client";

import { seedInitialIdentityCatalog } from "../../src/modules/identity/infrastructure/catalog-repository";
import { hashPassword } from "../../src/modules/identity/security/password";

export default async function globalSetup() {
  const runtimeUrl = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;
  const migrationUrl = process.env.TEST_MIGRATION_DATABASE_URL;
  if (!runtimeUrl || !migrationUrl) {
    throw new Error(
      "E2E authentication tests require runtime and migration test database URLs.",
    );
  }

  const runtime = new PrismaClient({ datasourceUrl: runtimeUrl });
  const migration = new PrismaClient({ datasourceUrl: migrationUrl });
  await Promise.all([runtime.$connect(), migration.$connect()]);
  await seedInitialIdentityCatalog(migration);

  const suffix = randomUUID().slice(0, 8);
  const username = `e2e.${suffix}`;
  const email = `e2e.${suffix}@example.test`;
  const password = `e2e password ${randomUUID()}`;
  const user = await runtime.user.create({
    data: {
      username,
      usernameNormalized: username,
      email,
      emailNormalized: email,
      displayName: "E2E Authentication User",
      status: "ACTIVE",
      passwordHash: await hashPassword(password),
    },
  });
  const cashier = await runtime.role.findUniqueOrThrow({
    where: { code: "cashier" },
  });
  await runtime.userRole.create({
    data: { userId: user.id, roleId: cashier.id },
  });

  process.env.LUMINA_E2E_USERNAME = username;
  process.env.LUMINA_E2E_EMAIL = email;
  process.env.LUMINA_E2E_PASSWORD = password;
  process.env.LUMINA_E2E_USER_ID = user.id;

  return async () => {
    await migration.session.deleteMany({ where: { userId: user.id } });
    await migration.userRole.deleteMany({ where: { userId: user.id } });
    await migration.user.update({
      where: { id: user.id },
      data: { status: "INACTIVE", passwordHash: null },
    });
    await Promise.all([runtime.$disconnect(), migration.$disconnect()]);
  };
}
