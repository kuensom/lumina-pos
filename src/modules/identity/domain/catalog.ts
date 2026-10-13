export type PermissionDefinition = {
  code: string;
  resource: string;
  action: string;
  description: string;
  requiresSuperAdmin: boolean;
};

export type RoleDefinition = {
  code: string;
  name: string;
  description: string;
  isSystem: boolean;
  isProtected: boolean;
  permissionCodes: readonly string[];
};

export const INITIAL_PERMISSIONS = [
  permission("dashboard", "view", "View the authenticated dashboard."),
  permission("users", "read", "Read the permitted staff directory."),
  permission("users", "create", "Create ordinary staff accounts."),
  permission("users", "update", "Update permitted staff accounts."),
  permission("users", "deactivate", "Deactivate permitted staff accounts."),
  permission("users", "activate", "Activate enrolled staff accounts."),
  permission("users", "lock", "Administratively lock staff accounts."),
  permission("users", "unlock", "Unlock staff accounts."),
  permission(
    "users",
    "reset_password",
    "Initiate ordinary staff password recovery.",
  ),
  permission(
    "users",
    "manage_super_admin",
    "Manage Super Administrator accounts.",
    true,
  ),
  permission(
    "users",
    "protected_recovery",
    "Initiate protected account recovery.",
    true,
  ),
  permission("roles", "read", "Read roles and their permissions."),
  permission("roles", "create", "Create configurable roles.", true),
  permission("roles", "update", "Update configurable roles.", true),
  permission("roles", "assign", "Assign non-privileged roles."),
  permission(
    "roles",
    "assign_privileged",
    "Assign protected or privileged roles.",
    true,
  ),
  permission("permissions", "read", "Read the permission catalogue."),
  permission("permissions", "assign", "Change role permission grants.", true),
  permission(
    "audit",
    "read",
    "Read permitted staff-administration audit events.",
  ),
  permission(
    "audit",
    "read_all",
    "Read all identity and access audit events.",
    true,
  ),
] as const satisfies readonly PermissionDefinition[];

const allPermissionCodes = INITIAL_PERMISSIONS.map(({ code }) => code);

export const INITIAL_ROLES = [
  role(
    "super_administrator",
    "Super Administrator",
    "Protected system administration role.",
    allPermissionCodes,
    true,
  ),
  role(
    "administrator",
    "Administrator",
    "Ordinary staff administration role.",
    [
      "dashboard:view",
      "users:read",
      "users:create",
      "users:update",
      "users:deactivate",
      "users:activate",
      "users:lock",
      "users:unlock",
      "users:reset_password",
      "roles:read",
      "roles:assign",
      "permissions:read",
      "audit:read",
    ],
  ),
  role(
    "supervisor",
    "Supervisor",
    "Supervisor with limited staff-directory access.",
    ["dashboard:view", "users:read"],
  ),
  role("cashier", "Cashier / Sales Staff", "Retail staff role placeholder.", [
    "dashboard:view",
  ]),
  role(
    "wholesale_sales",
    "Wholesale Sales Staff",
    "Wholesale staff role placeholder; no wholesale capability is implemented.",
    ["dashboard:view"],
  ),
] as const satisfies readonly RoleDefinition[];

function permission(
  resource: string,
  action: string,
  description: string,
  requiresSuperAdmin = false,
): PermissionDefinition {
  return {
    code: `${resource}:${action}`,
    resource,
    action,
    description,
    requiresSuperAdmin,
  };
}

function role(
  code: string,
  name: string,
  description: string,
  permissionCodes: readonly string[],
  isProtected = false,
): RoleDefinition {
  return {
    code,
    name,
    description,
    isSystem: true,
    isProtected,
    permissionCodes,
  };
}
