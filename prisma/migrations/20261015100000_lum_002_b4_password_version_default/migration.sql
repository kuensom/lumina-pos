-- Compatibility for existing trusted fixture/bootstrap writers that provide a
-- password hash without an explicit version. Enrollment-ready application
-- services explicitly write version zero until successful redemption.
ALTER TABLE "users" ALTER COLUMN "password_version" SET DEFAULT 1;
