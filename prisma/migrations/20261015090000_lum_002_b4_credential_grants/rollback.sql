-- Disposable development/test databases only. B4 is forward-only after use.
DROP TRIGGER IF EXISTS "users_email_verification_guard" ON "users";
DROP FUNCTION IF EXISTS "clear_changed_email_verification"();
DROP TABLE IF EXISTS "credential_grant_deliveries";
DROP INDEX IF EXISTS "password_reset_grants_one_open_purpose_key";
ALTER TABLE "password_reset_grants" DROP COLUMN IF EXISTS "delivery_channel", DROP COLUMN IF EXISTS "subject_email_version", DROP COLUMN IF EXISTS "subject_password_version", DROP COLUMN IF EXISTS "subject_status", DROP COLUMN IF EXISTS "issued_at";
ALTER TABLE "sessions" DROP COLUMN IF EXISTS "password_version";
ALTER TABLE "users" DROP COLUMN IF EXISTS "email_verified_at", DROP COLUMN IF EXISTS "email_version", DROP COLUMN IF EXISTS "password_version";
DROP TYPE IF EXISTS "CredentialDeliveryStatus";
DROP TYPE IF EXISTS "CredentialDeliveryChannel";
