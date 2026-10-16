-- Disposable development/test databases only.
ALTER TABLE "users" ALTER COLUMN "password_version" SET DEFAULT 0;
