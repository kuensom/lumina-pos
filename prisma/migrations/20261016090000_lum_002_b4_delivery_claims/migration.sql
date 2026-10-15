ALTER TYPE "CredentialDeliveryStatus" ADD VALUE 'CLAIMED';
ALTER TYPE "CredentialDeliveryStatus" ADD VALUE 'UNKNOWN';

ALTER TABLE "credential_grant_deliveries"
  ADD COLUMN "claim_token" UUID,
  ADD COLUMN "claim_expires_at" TIMESTAMPTZ(3),
  ADD CONSTRAINT "credential_grant_deliveries_claim_check" CHECK (
    ("claim_token" IS NULL) = ("claim_expires_at" IS NULL)
  );

CREATE UNIQUE INDEX "credential_grant_deliveries_claim_token_key"
  ON "credential_grant_deliveries" ("claim_token")
  WHERE "claim_token" IS NOT NULL;
