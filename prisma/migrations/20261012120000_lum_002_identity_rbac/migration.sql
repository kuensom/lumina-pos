-- LUM-002-B1 identity and RBAC foundation. All database names are explicit in
-- schema.prisma; the additional checks and triggers below are PostgreSQL-only.

CREATE TYPE "UserStatus" AS ENUM ('PENDING_PASSWORD', 'ACTIVE', 'INACTIVE', 'LOCKED');
CREATE TYPE "PasswordResetPurpose" AS ENUM ('INITIAL_ENROLMENT', 'ADMINISTRATOR_RESET', 'PROTECTED_RECOVERY');
CREATE TYPE "AuditOutcome" AS ENUM ('SUCCESS', 'DENIED', 'FAILURE');
CREATE TYPE "RateLimitScope" AS ENUM ('LOGIN_IDENTIFIER', 'LOGIN_NETWORK', 'RESET_ISSUE_USER', 'RESET_ISSUE_ACTOR', 'RESET_CONSUME_TOKEN', 'RESET_CONSUME_NETWORK');

CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "username" VARCHAR(32) NOT NULL,
    "username_normalized" VARCHAR(32) NOT NULL,
    "email" VARCHAR(320),
    "email_normalized" VARCHAR(320),
    "display_name" VARCHAR(120) NOT NULL,
    "password_hash" VARCHAR(512),
    "status" "UserStatus" NOT NULL DEFAULT 'PENDING_PASSWORD',
    "authz_version" INTEGER NOT NULL DEFAULT 1,
    "password_changed_at" TIMESTAMPTZ(3),
    "last_login_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "users_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "users_authz_version_check" CHECK ("authz_version" > 0),
    CONSTRAINT "users_username_normalized_check" CHECK (
      "username_normalized" = lower("username_normalized") AND
      "username_normalized" ~ '^[a-z0-9._-]{3,32}$'
    ),
    CONSTRAINT "users_username_canonical_check" CHECK ("username" = "username_normalized"),
    CONSTRAINT "users_email_pair_check" CHECK (
      ("email" IS NULL AND "email_normalized" IS NULL) OR
      ("email" IS NOT NULL AND "email_normalized" IS NOT NULL)
    ),
    CONSTRAINT "users_email_normalized_check" CHECK (
      "email_normalized" IS NULL OR (
        "email_normalized" = lower("email_normalized") AND
        "email_normalized" = lower(btrim("email")) AND
        "email_normalized" ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
      )
    ),
    CONSTRAINT "users_password_state_check" CHECK (
      "status" <> 'ACTIVE' OR "password_hash" IS NOT NULL
    )
);

CREATE TABLE "roles" (
    "id" UUID NOT NULL,
    "code" VARCHAR(80) NOT NULL,
    "name" VARCHAR(120) NOT NULL,
    "description" VARCHAR(500),
    "is_system" BOOLEAN NOT NULL DEFAULT false,
    "is_protected" BOOLEAN NOT NULL DEFAULT false,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "roles_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "roles_code_check" CHECK ("code" ~ '^[a-z][a-z0-9_]{1,79}$'),
    CONSTRAINT "roles_protected_system_check" CHECK (NOT "is_protected" OR "is_system"),
    CONSTRAINT "roles_canonical_protected_role_check" CHECK (
      NOT "is_protected" OR "code" = 'super_administrator'
    )
);

CREATE TABLE "permissions" (
    "id" UUID NOT NULL,
    "code" VARCHAR(120) NOT NULL,
    "resource" VARCHAR(60) NOT NULL,
    "action" VARCHAR(60) NOT NULL,
    "description" VARCHAR(500) NOT NULL,
    "requires_super_admin" BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT "permissions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "permissions_code_check" CHECK (
      "resource" ~ '^[a-z][a-z0-9_-]{1,59}$' AND
      "action" ~ '^[a-z][a-z0-9_-]{1,59}$' AND
      "code" = "resource" || ':' || "action"
    )
);

CREATE TABLE "user_roles" (
    "user_id" UUID NOT NULL,
    "role_id" UUID NOT NULL,
    "assigned_by_id" UUID,
    "assigned_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "user_roles_pkey" PRIMARY KEY ("user_id", "role_id")
);

CREATE TABLE "role_permissions" (
    "role_id" UUID NOT NULL,
    "permission_id" UUID NOT NULL,
    "granted_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "role_permissions_pkey" PRIMARY KEY ("role_id", "permission_id")
);

CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "authz_version" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idle_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "revoke_reason" VARCHAR(120),
    "ip_hash" CHAR(64),
    "user_agent_summary" VARCHAR(250),
    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "sessions_authz_version_check" CHECK ("authz_version" > 0),
    CONSTRAINT "sessions_token_hash_check" CHECK ("token_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "sessions_expiry_check" CHECK (
      "created_at" <= "last_seen_at" AND
      "last_seen_at" <= "idle_expires_at" AND
      "idle_expires_at" <= "absolute_expires_at"
    ),
    CONSTRAINT "sessions_idle_lifetime_check" CHECK (
      "idle_expires_at" <= LEAST(
        "last_seen_at" + INTERVAL '60 minutes',
        "absolute_expires_at"
      )
    ),
    CONSTRAINT "sessions_absolute_lifetime_check" CHECK (
      "absolute_expires_at" <= "created_at" + INTERVAL '12 hours'
    ),
    CONSTRAINT "sessions_revoked_at_check" CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at"),
    CONSTRAINT "sessions_revoke_reason_check" CHECK (("revoked_at" IS NULL) = ("revoke_reason" IS NULL)),
    CONSTRAINT "sessions_ip_hash_check" CHECK ("ip_hash" IS NULL OR "ip_hash" ~ '^[0-9a-f]{64}$')
);

CREATE TABLE "password_reset_grants" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "requested_by_id" UUID,
    "token_hash" CHAR(64) NOT NULL,
    "purpose" "PasswordResetPurpose" NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "password_reset_grants_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "password_reset_grants_token_hash_check" CHECK ("token_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "password_reset_grants_expiry_check" CHECK ("expires_at" > "created_at"),
    CONSTRAINT "password_reset_grants_ordinary_expiry_check" CHECK (
      "purpose" = 'PROTECTED_RECOVERY' OR
      "expires_at" <= "created_at" + INTERVAL '15 minutes'
    ),
    CONSTRAINT "password_reset_grants_consumed_at_check" CHECK ("consumed_at" IS NULL OR "consumed_at" >= "created_at"),
    CONSTRAINT "password_reset_grants_revoked_at_check" CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at"),
    CONSTRAINT "password_reset_grants_terminal_state_check" CHECK ("consumed_at" IS NULL OR "revoked_at" IS NULL),
    CONSTRAINT "password_reset_grants_requester_check" CHECK (
      ("purpose" = 'INITIAL_ENROLMENT' AND "requested_by_id" IS NULL) OR
      ("purpose" <> 'INITIAL_ENROLMENT' AND "requested_by_id" IS NOT NULL)
    )
);

CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "actor_user_id" UUID,
    "event_type" VARCHAR(120) NOT NULL,
    "target_type" VARCHAR(80),
    "target_id" VARCHAR(120),
    "outcome" "AuditOutcome" NOT NULL,
    "correlation_id" VARCHAR(120) NOT NULL,
    "ip_hash" CHAR(64),
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "audit_events_type_check" CHECK ("event_type" ~ '^[a-z][a-z0-9_.-]{2,119}$'),
    CONSTRAINT "audit_events_target_check" CHECK (("target_type" IS NULL) = ("target_id" IS NULL)),
    CONSTRAINT "audit_events_ip_hash_check" CHECK ("ip_hash" IS NULL OR "ip_hash" ~ '^[0-9a-f]{64}$')
);

CREATE TABLE "auth_rate_limit_buckets" (
    "id" UUID NOT NULL,
    "scope" "RateLimitScope" NOT NULL,
    "subject_hash" CHAR(64) NOT NULL,
    "window_start" TIMESTAMPTZ(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "blocked_until" TIMESTAMPTZ(3),
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "auth_rate_limit_buckets_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "auth_rate_limit_buckets_attempts_check" CHECK ("attempts" >= 0),
    CONSTRAINT "auth_rate_limit_buckets_subject_hash_check" CHECK ("subject_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "auth_rate_limit_buckets_blocked_until_check" CHECK ("blocked_until" IS NULL OR "blocked_until" >= "window_start")
);

CREATE UNIQUE INDEX "users_username_normalized_key" ON "users"("username_normalized");
CREATE UNIQUE INDEX "users_email_normalized_key" ON "users"("email_normalized");
CREATE INDEX "users_status_idx" ON "users"("status");
CREATE UNIQUE INDEX "roles_code_key" ON "roles"("code");
CREATE INDEX "roles_is_active_idx" ON "roles"("is_active");
CREATE UNIQUE INDEX "permissions_code_key" ON "permissions"("code");
CREATE UNIQUE INDEX "permissions_resource_action_key" ON "permissions"("resource", "action");
CREATE INDEX "user_roles_role_id_idx" ON "user_roles"("role_id");
CREATE INDEX "user_roles_assigned_by_id_idx" ON "user_roles"("assigned_by_id");
CREATE INDEX "role_permissions_permission_id_idx" ON "role_permissions"("permission_id");
CREATE UNIQUE INDEX "sessions_token_hash_key" ON "sessions"("token_hash");
CREATE INDEX "sessions_user_id_revoked_at_idx" ON "sessions"("user_id", "revoked_at");
CREATE INDEX "sessions_idle_expires_at_idx" ON "sessions"("idle_expires_at");
CREATE INDEX "sessions_absolute_expires_at_idx" ON "sessions"("absolute_expires_at");
CREATE UNIQUE INDEX "password_reset_grants_token_hash_key" ON "password_reset_grants"("token_hash");
CREATE INDEX "password_reset_grants_user_id_expires_at_idx" ON "password_reset_grants"("user_id", "expires_at");
CREATE INDEX "password_reset_grants_requested_by_id_created_at_idx" ON "password_reset_grants"("requested_by_id", "created_at");
CREATE INDEX "audit_events_actor_user_id_created_at_idx" ON "audit_events"("actor_user_id", "created_at");
CREATE INDEX "audit_events_event_type_created_at_idx" ON "audit_events"("event_type", "created_at");
CREATE INDEX "audit_events_target_created_at_idx" ON "audit_events"("target_type", "target_id", "created_at");
CREATE INDEX "audit_events_correlation_id_idx" ON "audit_events"("correlation_id");
CREATE INDEX "auth_rate_limit_buckets_blocked_until_idx" ON "auth_rate_limit_buckets"("blocked_until");
CREATE UNIQUE INDEX "auth_rate_limit_buckets_scope_subject_window_key" ON "auth_rate_limit_buckets"("scope", "subject_hash", "window_start");

ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_assigned_by_id_fkey" FOREIGN KEY ("assigned_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_permission_id_fkey" FOREIGN KEY ("permission_id") REFERENCES "permissions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "password_reset_grants" ADD CONSTRAINT "password_reset_grants_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "password_reset_grants" ADD CONSTRAINT "password_reset_grants_requested_by_id_fkey" FOREIGN KEY ("requested_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actor_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- System role identifiers and security classifications are migration-owned.
CREATE FUNCTION "reject_role_security_update"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (
    (NEW).code IS DISTINCT FROM (OLD).code OR
    (NEW).is_system IS DISTINCT FROM (OLD).is_system OR
    (NEW).is_protected IS DISTINCT FROM (OLD).is_protected
  ) THEN
    RAISE EXCEPTION 'role security fields are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION "reject_permission_security_update"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (
    (NEW).code IS DISTINCT FROM (OLD).code OR
    (NEW).resource IS DISTINCT FROM (OLD).resource OR
    (NEW).action IS DISTINCT FROM (OLD).action OR
    (NEW).requires_super_admin IS DISTINCT FROM (OLD).requires_super_admin
  ) THEN
    RAISE EXCEPTION 'permission security fields are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "roles_security_fields_immutable"
BEFORE UPDATE ON "roles"
FOR EACH ROW EXECUTE FUNCTION "reject_role_security_update"();

CREATE TRIGGER "permissions_security_fields_immutable"
BEFORE UPDATE ON "permissions"
FOR EACH ROW EXECUTE FUNCTION "reject_permission_security_update"();

-- Protected capabilities may only belong to a protected system role and may
-- not be removed from it by runtime catalogue operations.
CREATE FUNCTION "enforce_protected_permission_grant"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  role_is_protected boolean;
  permission_is_protected boolean;
  caller_is_catalog_owner boolean;
BEGIN
  SELECT pg_has_role(current_user, c.relowner, 'USAGE')
  INTO caller_is_catalog_owner
  FROM pg_class AS c
  WHERE c.oid = 'role_permissions'::regclass;

  IF TG_OP = 'DELETE' THEN
    SELECT "is_protected" INTO role_is_protected FROM "roles" WHERE "id" = (OLD).role_id;
    SELECT "requires_super_admin" INTO permission_is_protected FROM "permissions" WHERE "id" = (OLD).permission_id;
    IF role_is_protected AND NOT caller_is_catalog_owner THEN
      RAISE EXCEPTION 'protected capability grants are immutable';
    END IF;
    RETURN OLD;
  END IF;

  SELECT "is_protected" INTO role_is_protected FROM "roles" WHERE "id" = (NEW).role_id;
  SELECT "requires_super_admin" INTO permission_is_protected FROM "permissions" WHERE "id" = (NEW).permission_id;
  IF permission_is_protected AND NOT role_is_protected THEN
    RAISE EXCEPTION 'protected capabilities require a protected role';
  END IF;
  IF role_is_protected AND NOT caller_is_catalog_owner THEN
    RAISE EXCEPTION 'protected role grants are migration-owned';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "role_permissions_protected_capability_guard"
BEFORE INSERT OR UPDATE OR DELETE ON "role_permissions"
FOR EACH ROW EXECUTE FUNCTION "enforce_protected_permission_grant"();

-- Membership or permission changes invalidate authorization for every affected
-- active user inside the same transaction. A stale session then fails its
-- authzVersion comparison even before explicit session revocation is added.
CREATE FUNCTION "invalidate_role_authorization"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  affected_role_id uuid;
BEGIN
  affected_role_id := CASE WHEN TG_OP = 'DELETE' THEN (OLD).role_id ELSE (NEW).role_id END;
  UPDATE "users" AS u
  SET "authz_version" = u."authz_version" + 1,
      "updated_at" = CURRENT_TIMESTAMP
  WHERE u."status" = 'ACTIVE'
    AND EXISTS (
      SELECT 1 FROM "user_roles" AS ur
      WHERE ur."user_id" = u."id" AND ur."role_id" = affected_role_id
    );

  IF TG_OP = 'UPDATE' AND (OLD).role_id IS DISTINCT FROM (NEW).role_id THEN
    UPDATE "users" AS u
    SET "authz_version" = u."authz_version" + 1,
        "updated_at" = CURRENT_TIMESTAMP
    WHERE u."status" = 'ACTIVE'
      AND EXISTS (
        SELECT 1 FROM "user_roles" AS ur
        WHERE ur."user_id" = u."id" AND ur."role_id" = (OLD).role_id
      );
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER "role_permissions_invalidate_authorization"
AFTER INSERT OR UPDATE OR DELETE ON "role_permissions"
FOR EACH ROW EXECUTE FUNCTION "invalidate_role_authorization"();

CREATE FUNCTION "invalidate_user_role_authorization"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  affected_user_id uuid;
BEGIN
  affected_user_id := CASE WHEN TG_OP = 'DELETE' THEN (OLD).user_id ELSE (NEW).user_id END;
  UPDATE "users"
  SET "authz_version" = "authz_version" + 1,
      "updated_at" = CURRENT_TIMESTAMP
  WHERE "id" = affected_user_id AND "status" = 'ACTIVE';

  IF TG_OP = 'UPDATE' AND (OLD).user_id IS DISTINCT FROM (NEW).user_id THEN
    UPDATE "users"
    SET "authz_version" = "authz_version" + 1,
        "updated_at" = CURRENT_TIMESTAMP
    WHERE "id" = (OLD).user_id AND "status" = 'ACTIVE';
  END IF;

  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER "user_roles_invalidate_authorization"
AFTER INSERT OR UPDATE OR DELETE ON "user_roles"
FOR EACH ROW EXECUTE FUNCTION "invalidate_user_role_authorization"();

-- Audit records are append-only even if application code accidentally attempts
-- an update or delete. Production must additionally deny those table grants to
-- the runtime database role; migrations use a distinct owner role.
CREATE FUNCTION "reject_audit_event_mutation"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events are append-only';
END;
$$;

CREATE TRIGGER "audit_events_append_only"
BEFORE UPDATE OR DELETE ON "audit_events"
FOR EACH ROW EXECUTE FUNCTION "reject_audit_event_mutation"();

CREATE TRIGGER "audit_events_no_truncate"
BEFORE TRUNCATE ON "audit_events"
FOR EACH STATEMENT EXECUTE FUNCTION "reject_audit_event_mutation"();
