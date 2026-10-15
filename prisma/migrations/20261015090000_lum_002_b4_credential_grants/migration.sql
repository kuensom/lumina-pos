ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_ISSUE_ACTOR';
ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_ISSUE_USER';
ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_EMAIL_USER';
ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_VOUCHER_USER';
ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_CONSUME_TOKEN';
ALTER TYPE "RateLimitScope" ADD VALUE 'CREDENTIAL_CONSUME_NETWORK';
CREATE TYPE "CredentialDeliveryChannel" AS ENUM ('EMAIL', 'IN_PERSON');
CREATE TYPE "CredentialDeliveryStatus" AS ENUM ('QUEUED', 'DISPLAYED', 'ACKNOWLEDGED', 'ACCEPTED', 'FAILED', 'CANCELLED');

ALTER TABLE "users"
  ADD COLUMN "email_verified_at" TIMESTAMPTZ(3),
  ADD COLUMN "email_version" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "password_version" INTEGER NOT NULL DEFAULT 0;
UPDATE "users" SET "password_version" = 1 WHERE "password_hash" IS NOT NULL;
ALTER TABLE "users"
  ADD CONSTRAINT "users_email_version_check" CHECK ("email_version" >= 0),
  ADD CONSTRAINT "users_password_version_check" CHECK ("password_version" >= 0),
  ADD CONSTRAINT "users_password_version_hash_check" CHECK ("password_hash" IS NULL OR "password_version" > 0),
  ADD CONSTRAINT "users_verified_email_check" CHECK ("email_verified_at" IS NULL OR "email_normalized" IS NOT NULL);

ALTER TABLE "sessions" ADD COLUMN "password_version" INTEGER DEFAULT 1;
UPDATE "sessions" AS s SET "password_version" = u."password_version" FROM "users" AS u WHERE u."id" = s."user_id";
ALTER TABLE "sessions" ALTER COLUMN "password_version" SET NOT NULL;
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_password_version_check" CHECK ("password_version" > 0);

ALTER TABLE "password_reset_grants"
  ADD COLUMN "delivery_channel" "CredentialDeliveryChannel" DEFAULT 'IN_PERSON',
  ADD COLUMN "subject_email_version" INTEGER,
  ADD COLUMN "subject_password_version" INTEGER DEFAULT 0,
  ADD COLUMN "subject_status" "UserStatus" DEFAULT 'PENDING_PASSWORD',
  ADD COLUMN "issued_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
-- Historical, unconsumed B1 placeholders are invalidated rather than upgraded
-- into usable credentials without a known delivery channel.
UPDATE "password_reset_grants" SET "revoked_at" = COALESCE("revoked_at", CURRENT_TIMESTAMP) WHERE "consumed_at" IS NULL;
UPDATE "password_reset_grants" AS g SET
  "delivery_channel" = 'IN_PERSON',
  "subject_password_version" = u."password_version",
  "subject_status" = u."status"
FROM "users" AS u WHERE u."id" = g."user_id";
ALTER TABLE "password_reset_grants"
  ALTER COLUMN "delivery_channel" SET NOT NULL,
  ALTER COLUMN "subject_password_version" SET NOT NULL,
  ALTER COLUMN "subject_status" SET NOT NULL,
  DROP CONSTRAINT "password_reset_grants_requester_check",
  DROP CONSTRAINT "password_reset_grants_ordinary_expiry_check",
  ADD CONSTRAINT "password_reset_grants_requester_check" CHECK (
    "purpose" = 'PROTECTED_RECOVERY' OR "requested_by_id" IS NOT NULL
  ),
  ADD CONSTRAINT "password_reset_grants_b4_expiry_check" CHECK (
    "purpose" = 'PROTECTED_RECOVERY' OR "expires_at" <= "created_at" + INTERVAL '15 minutes'
  ),
  ADD CONSTRAINT "password_reset_grants_email_binding_check" CHECK (
    ("delivery_channel" = 'EMAIL' AND "subject_email_version" IS NOT NULL) OR
    ("delivery_channel" = 'IN_PERSON' AND "subject_email_version" IS NULL)
  ),
  ADD CONSTRAINT "password_reset_grants_version_check" CHECK (
    "subject_password_version" >= 0 AND ("subject_email_version" IS NULL OR "subject_email_version" >= 0)
  );
CREATE UNIQUE INDEX "password_reset_grants_one_open_purpose_key"
  ON "password_reset_grants" ("user_id", "purpose")
  WHERE "consumed_at" IS NULL AND "revoked_at" IS NULL;

CREATE TABLE "credential_grant_deliveries" (
  "id" UUID NOT NULL,
  "grant_id" UUID NOT NULL,
  "user_id" UUID NOT NULL,
  "channel" "CredentialDeliveryChannel" NOT NULL,
  "status" "CredentialDeliveryStatus" NOT NULL,
  "destination_hash" CHAR(64),
  "provider_message_id" VARCHAR(200),
  "attempt_count" INTEGER NOT NULL DEFAULT 0,
  "last_attempt_at" TIMESTAMPTZ(3),
  "delivered_at" TIMESTAMPTZ(3),
  "acknowledged_at" TIMESTAMPTZ(3),
  "failure_code" VARCHAR(80),
  "encrypted_payload" TEXT,
  "payload_expires_at" TIMESTAMPTZ(3),
  "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(3) NOT NULL,
  CONSTRAINT "credential_grant_deliveries_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "credential_grant_deliveries_attempt_check" CHECK ("attempt_count" BETWEEN 0 AND 3),
  CONSTRAINT "credential_grant_deliveries_destination_check" CHECK ("destination_hash" IS NULL OR "destination_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "credential_grant_deliveries_payload_check" CHECK (("encrypted_payload" IS NULL) = ("payload_expires_at" IS NULL))
);
CREATE INDEX "credential_grant_deliveries_grant_created_idx" ON "credential_grant_deliveries"("grant_id", "created_at");
CREATE INDEX "credential_grant_deliveries_status_created_idx" ON "credential_grant_deliveries"("status", "created_at");
ALTER TABLE "credential_grant_deliveries" ADD CONSTRAINT "credential_grant_deliveries_grant_id_fkey" FOREIGN KEY ("grant_id") REFERENCES "password_reset_grants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "credential_grant_deliveries" ADD CONSTRAINT "credential_grant_deliveries_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE FUNCTION "clear_changed_email_verification"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.email_normalized IS DISTINCT FROM OLD.email_normalized THEN
    NEW.email_verified_at := NULL;
    NEW.email_version := OLD.email_version + 1;
    UPDATE "password_reset_grants" SET "revoked_at" = CURRENT_TIMESTAMP
      WHERE "user_id" = OLD.id AND "delivery_channel" = 'EMAIL'
        AND "consumed_at" IS NULL AND "revoked_at" IS NULL;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER "users_email_verification_guard" BEFORE UPDATE OF "email_normalized" ON "users"
FOR EACH ROW EXECUTE FUNCTION "clear_changed_email_verification"();

INSERT INTO "permissions" ("id", "code", "resource", "action", "description", "requires_super_admin") VALUES
  (gen_random_uuid(), 'users:issue_enrolment', 'users', 'issue_enrolment', 'Issue ordinary staff enrolment credentials.', false),
  (gen_random_uuid(), 'users:recover_administrator', 'users', 'recover_administrator', 'Recover Administrator credentials.', true)
ON CONFLICT ("code") DO NOTHING;
INSERT INTO "role_permissions" ("role_id", "permission_id")
SELECT r.id, p.id FROM "roles" r CROSS JOIN "permissions" p
WHERE (r.code = 'administrator' AND p.code = 'users:issue_enrolment')
   OR (r.code = 'super_administrator' AND p.code IN ('users:issue_enrolment', 'users:recover_administrator'))
ON CONFLICT DO NOTHING;
