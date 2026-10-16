-- Disposable development/test databases only. B4 delivery claims are
-- forward-only after production use.
DROP INDEX IF EXISTS "credential_grant_deliveries_claim_token_key";
ALTER TABLE "credential_grant_deliveries"
  DROP CONSTRAINT IF EXISTS "credential_grant_deliveries_claim_check",
  DROP COLUMN IF EXISTS "claim_token",
  DROP COLUMN IF EXISTS "claim_expires_at";
