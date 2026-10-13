-- TEST/DISPOSABLE DATABASES ONLY. Production rollback must be forward-only.
DROP TRIGGER IF EXISTS "user_roles_last_super_administrator_guard" ON "user_roles";
DROP TRIGGER IF EXISTS "users_last_super_administrator_guard" ON "users";
DROP FUNCTION IF EXISTS "enforce_last_super_administrator_membership"();
DROP FUNCTION IF EXISTS "enforce_last_super_administrator_user_status"();
DROP FUNCTION IF EXISTS "lock_super_administrator_invariant"();

DELETE FROM "role_permissions"
WHERE "permission_id" IN (
  SELECT "id" FROM "permissions"
  WHERE "code" IN ('users:activate', 'users:lock', 'users:unlock')
);
DELETE FROM "permissions"
WHERE "code" IN ('users:activate', 'users:lock', 'users:unlock');
