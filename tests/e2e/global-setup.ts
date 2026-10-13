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

  const administratorUsername = `e2e.admin.${suffix}`;
  const administratorPassword = `e2e administrator ${randomUUID()}`;
  const administrator = await runtime.user.create({
    data: {
      username: administratorUsername,
      usernameNormalized: administratorUsername,
      displayName: "E2E Administrator",
      status: "ACTIVE",
      passwordHash: await hashPassword(administratorPassword),
    },
  });
  const administratorRole = await runtime.role.findUniqueOrThrow({
    where: { code: "administrator" },
  });
  await runtime.userRole.create({
    data: { userId: administrator.id, roleId: administratorRole.id },
  });

  const supervisorUsername = `e2e.supervisor.${suffix}`;
  const supervisorPassword = `e2e supervisor ${randomUUID()}`;
  const supervisor = await createRoleFixture({
    runtime,
    username: supervisorUsername,
    password: supervisorPassword,
    displayName: "E2E Supervisor",
    roleCode: "supervisor",
  });
  const superUsername = `e2e.super.${suffix}`;
  const superPassword = `e2e super administrator ${randomUUID()}`;
  const superAdministrator = await createRoleFixture({
    runtime,
    username: superUsername,
    password: superPassword,
    displayName: "E2E Protected Administrator",
    roleCode: "super_administrator",
  });

  process.env.LUMINA_E2E_USERNAME = username;
  process.env.LUMINA_E2E_EMAIL = email;
  process.env.LUMINA_E2E_PASSWORD = password;
  process.env.LUMINA_E2E_USER_ID = user.id;
  process.env.LUMINA_E2E_ADMIN_USERNAME = administratorUsername;
  process.env.LUMINA_E2E_ADMIN_PASSWORD = administratorPassword;
  process.env.LUMINA_E2E_ADMIN_ID = administrator.id;
  process.env.LUMINA_E2E_SUPERVISOR_USERNAME = supervisorUsername;
  process.env.LUMINA_E2E_SUPERVISOR_PASSWORD = supervisorPassword;
  process.env.LUMINA_E2E_SUPER_USERNAME = superUsername;
  process.env.LUMINA_E2E_SUPER_PASSWORD = superPassword;
  process.env.LUMINA_E2E_SUPER_ID = superAdministrator.id;

  return async () => {
    const userIds = [
      user.id,
      administrator.id,
      supervisor.id,
      superAdministrator.id,
    ];
    await migration.session.deleteMany({ where: { userId: { in: userIds } } });
    await migration.userRole.deleteMany({ where: { userId: { in: userIds } } });
    await migration.user.updateMany({
      where: { id: { in: userIds } },
      data: { status: "INACTIVE", passwordHash: null },
    });
    await Promise.all([runtime.$disconnect(), migration.$disconnect()]);
  };
}

async function createRoleFixture(input: {
  runtime: PrismaClient;
  username: string;
  password: string;
  displayName: string;
  roleCode: string;
}) {
  const role = await input.runtime.role.findUniqueOrThrow({
    where: { code: input.roleCode },
  });
  return input.runtime.user.create({
    data: {
      username: input.username,
      usernameNormalized: input.username,
      displayName: input.displayName,
      status: "ACTIVE",
      passwordHash: await hashPassword(input.password),
      roles: { create: { roleId: role.id } },
    },
  });
}
