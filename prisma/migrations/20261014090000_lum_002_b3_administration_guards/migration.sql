-- LUM-002-B3 additive catalogue upgrade and last-active-Super-Administrator
-- invariant. The migration owner is the only database-level emergency bypass;
-- use of that credential is governed by the independently approved break-glass
-- process and is never exposed to the application runtime.

INSERT INTO "permissions" (
  "id", "code", "resource", "action", "description", "requires_super_admin"
) VALUES
  (gen_random_uuid(), 'users:activate', 'users', 'activate', 'Activate enrolled staff accounts.', false),
  (gen_random_uuid(), 'users:lock', 'users', 'lock', 'Administratively lock staff accounts.', false),
  (gen_random_uuid(), 'users:unlock', 'users', 'unlock', 'Unlock staff accounts.', false)
ON CONFLICT ("code") DO NOTHING;

INSERT INTO "role_permissions" ("role_id", "permission_id")
SELECT r."id", p."id"
FROM "roles" r
CROSS JOIN "permissions" p
WHERE r."code" IN ('administrator', 'super_administrator')
  AND p."code" IN ('users:activate', 'users:lock', 'users:unlock')
ON CONFLICT ("role_id", "permission_id") DO NOTHING;

CREATE FUNCTION "lock_super_administrator_invariant"() RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('lumina:last-active-super-administrator', 0)
  );
END;
$$;

CREATE FUNCTION "enforce_last_super_administrator_user_status"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  caller_is_catalog_owner boolean;
  remaining_active bigint;
BEGIN
  IF (OLD).status <> 'ACTIVE' OR (NEW).status = 'ACTIVE' THEN
    RETURN NEW;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM "user_roles" ur
    JOIN "roles" r ON r."id" = ur."role_id"
    WHERE ur."user_id" = (OLD).id
      AND r."code" = 'super_administrator'
      AND r."is_protected" = true
      AND r."is_active" = true
  ) THEN
    RETURN NEW;
  END IF;

  SELECT pg_has_role(current_user, c.relowner, 'USAGE')
  INTO caller_is_catalog_owner
  FROM pg_class c
  WHERE c.oid = 'users'::regclass;
  IF caller_is_catalog_owner THEN
    RETURN NEW;
  END IF;

  PERFORM "lock_super_administrator_invariant"();
  SELECT count(*) INTO remaining_active
  FROM "users" u
  JOIN "user_roles" ur ON ur."user_id" = u."id"
  JOIN "roles" r ON r."id" = ur."role_id"
  WHERE u."id" <> (OLD).id
    AND u."status" = 'ACTIVE'
    AND r."code" = 'super_administrator'
    AND r."is_protected" = true
    AND r."is_active" = true;

  IF remaining_active = 0 THEN
    RAISE EXCEPTION 'cannot remove the last active Super Administrator';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "enforce_last_super_administrator_membership"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  caller_is_catalog_owner boolean;
  protected_role_id uuid;
  remaining_active bigint;
BEGIN
  SELECT "id" INTO protected_role_id
  FROM "roles"
  WHERE "code" = 'super_administrator'
    AND "is_protected" = true
    AND "is_active" = true;

  IF protected_role_id IS NULL OR (OLD).role_id <> protected_role_id THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW).role_id = protected_role_id THEN
    RETURN NEW;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM "users" WHERE "id" = (OLD).user_id AND "status" = 'ACTIVE'
  ) THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;

  SELECT pg_has_role(current_user, c.relowner, 'USAGE')
  INTO caller_is_catalog_owner
  FROM pg_class c
  WHERE c.oid = 'user_roles'::regclass;
  IF caller_is_catalog_owner THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;

  PERFORM "lock_super_administrator_invariant"();
  SELECT count(*) INTO remaining_active
  FROM "users" u
  JOIN "user_roles" ur ON ur."user_id" = u."id"
  WHERE ur."role_id" = protected_role_id
    AND ur."user_id" <> (OLD).user_id
    AND u."status" = 'ACTIVE';

  IF remaining_active = 0 THEN
    RAISE EXCEPTION 'cannot remove the last active Super Administrator';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER "users_last_super_administrator_guard"
BEFORE UPDATE OF "status" ON "users"
FOR EACH ROW EXECUTE FUNCTION "enforce_last_super_administrator_user_status"();

CREATE TRIGGER "user_roles_last_super_administrator_guard"
BEFORE UPDATE OR DELETE ON "user_roles"
FOR EACH ROW EXECUTE FUNCTION "enforce_last_super_administrator_membership"();
