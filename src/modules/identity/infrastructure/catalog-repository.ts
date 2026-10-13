import type { Prisma, PrismaClient } from "@prisma/client";

import { INITIAL_PERMISSIONS, INITIAL_ROLES } from "../domain/catalog";
import { retrySerializableTransaction } from "./serializable-retry";

type CatalogTransaction = Pick<
  Prisma.TransactionClient,
  "permission" | "role" | "rolePermission"
>;

export async function seedInitialIdentityCatalog(
  prisma: PrismaClient,
): Promise<void> {
  await retrySerializableTransaction(() =>
    prisma.$transaction(
      async (transaction) => {
        await insertAndVerifyPermissions(transaction);
        await insertAndVerifyRoles(transaction);
        await insertInitialGrants(transaction);
      },
      { isolationLevel: "Serializable" },
    ),
  );
}

async function insertAndVerifyPermissions(
  transaction: CatalogTransaction,
): Promise<void> {
  await transaction.permission.createMany({
    data: [...INITIAL_PERMISSIONS],
    skipDuplicates: true,
  });

  const persisted = await transaction.permission.findMany({
    where: { code: { in: INITIAL_PERMISSIONS.map(({ code }) => code) } },
  });

  for (const expected of INITIAL_PERMISSIONS) {
    const actual = persisted.find(({ code }) => code === expected.code);
    if (
      !actual ||
      actual.resource !== expected.resource ||
      actual.action !== expected.action ||
      actual.requiresSuperAdmin !== expected.requiresSuperAdmin
    ) {
      throw new Error(`Permission catalogue conflict for ${expected.code}.`);
    }
  }
}

async function insertAndVerifyRoles(
  transaction: CatalogTransaction,
): Promise<void> {
  await transaction.role.createMany({
    data: INITIAL_ROLES.map(
      ({ code, name, description, isSystem, isProtected }) => ({
        code,
        name,
        description,
        isSystem,
        isProtected,
      }),
    ),
    skipDuplicates: true,
  });

  const persisted = await transaction.role.findMany({
    where: { code: { in: INITIAL_ROLES.map(({ code }) => code) } },
  });

  for (const expected of INITIAL_ROLES) {
    const actual = persisted.find(({ code }) => code === expected.code);
    if (
      !actual ||
      actual.isSystem !== expected.isSystem ||
      actual.isProtected !== expected.isProtected
    ) {
      throw new Error(`Role catalogue conflict for ${expected.code}.`);
    }
  }
}

async function insertInitialGrants(
  transaction: CatalogTransaction,
): Promise<void> {
  const [roles, permissions] = await Promise.all([
    transaction.role.findMany({
      where: { code: { in: INITIAL_ROLES.map(({ code }) => code) } },
      select: { id: true, code: true },
    }),
    transaction.permission.findMany({
      where: { code: { in: INITIAL_PERMISSIONS.map(({ code }) => code) } },
      select: { id: true, code: true },
    }),
  ]);

  const roleIds = new Map(roles.map(({ code, id }) => [code, id]));
  const permissionIds = new Map(permissions.map(({ code, id }) => [code, id]));
  const grants: Prisma.RolePermissionCreateManyInput[] = [];

  for (const roleDefinition of INITIAL_ROLES) {
    const roleId = roleIds.get(roleDefinition.code);
    if (!roleId) {
      throw new Error(`Seeded role is missing: ${roleDefinition.code}.`);
    }

    for (const permissionCode of roleDefinition.permissionCodes) {
      const permissionId = permissionIds.get(permissionCode);
      if (!permissionId) {
        throw new Error(`Seeded permission is missing: ${permissionCode}.`);
      }
      grants.push({ roleId, permissionId });
    }
  }

  await transaction.rolePermission.createMany({
    data: grants,
    skipDuplicates: true,
  });
}
