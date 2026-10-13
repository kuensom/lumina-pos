-- Manual rollback for an empty/non-production LUM-002-B1 database only.
-- Do not run after real identity or audit data exists; use a reviewed forward
-- migration instead. Prisma does not execute this file automatically.

DROP TRIGGER IF EXISTS "audit_events_append_only" ON "audit_events";
DROP TRIGGER IF EXISTS "audit_events_no_truncate" ON "audit_events";
DROP FUNCTION IF EXISTS "reject_audit_event_mutation"();
DROP TRIGGER IF EXISTS "permissions_security_fields_immutable" ON "permissions";
DROP FUNCTION IF EXISTS "reject_permission_security_update"();
DROP TRIGGER IF EXISTS "roles_activity_invalidate_authorization" ON "roles";
DROP FUNCTION IF EXISTS "invalidate_role_activity_authorization"();
DROP TRIGGER IF EXISTS "roles_catalog_guard" ON "roles";
DROP FUNCTION IF EXISTS "enforce_role_catalog_guard"();
DROP TRIGGER IF EXISTS "user_roles_invalidate_authorization" ON "user_roles";
DROP FUNCTION IF EXISTS "invalidate_user_role_authorization"();
DROP TRIGGER IF EXISTS "role_permissions_invalidate_authorization" ON "role_permissions";
DROP FUNCTION IF EXISTS "invalidate_role_authorization"();
DROP TRIGGER IF EXISTS "role_permissions_protected_capability_guard" ON "role_permissions";
DROP FUNCTION IF EXISTS "enforce_protected_permission_grant"();

DROP TABLE IF EXISTS "auth_rate_limit_buckets";
DROP TABLE IF EXISTS "audit_events";
DROP TABLE IF EXISTS "password_reset_grants";
DROP TABLE IF EXISTS "sessions";
DROP TABLE IF EXISTS "role_permissions";
DROP TABLE IF EXISTS "user_roles";
DROP TABLE IF EXISTS "permissions";
DROP TABLE IF EXISTS "roles";
DROP TABLE IF EXISTS "users";

DROP TYPE IF EXISTS "RateLimitScope";
DROP TYPE IF EXISTS "AuditOutcome";
DROP TYPE IF EXISTS "PasswordResetPurpose";
DROP TYPE IF EXISTS "UserStatus";
