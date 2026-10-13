# Lumina POS

Lumina POS is a planned cloud-hosted point-of-sale system for a shop in Thimphu, Bhutan. This repository contains the application foundation and LUM-002 authentication/RBAC foundation. It provides staff username-or-email/password authentication and server-enforced sessions, but not password recovery, user administration, checkout, payments, inventory operations, or production infrastructure.

## Prerequisites

- Node.js `>=20.9.0` (Node 20 LTS is recommended; `.nvmrc` is provided)
- npm `>=10`
- Docker Engine with Docker Compose v2
- For browser tests, a supported Playwright Chromium installation

Dependency versions are exact-pinned in `package.json` and reproduced by `package-lock.json`.

## First run

```sh
nvm use
npm ci
cp .env.example .env
docker compose up -d
npm run prisma:generate
npm run prisma:validate
npm run db:roles -- create
DATABASE_URL="$MIGRATION_DATABASE_URL" npx prisma migrate deploy
npm run db:roles -- grant
npm run prisma:connect
npm run dev
```

Open <http://localhost:3000>. The health endpoint is available at <http://localhost:3000/api/health>.

The `.env.example` values are placeholders for local development. Replace every password in your untracked `.env`; do not reuse any outside local development. The Docker owner, migration owner, and runtime application role must remain distinct. The application uses only `DATABASE_URL`; migration commands temporarily receive `MIGRATION_DATABASE_URL`.

Generate independent local values for `NEXTAUTH_SECRET`, `SESSION_DIGEST_KEY`
and `RATE_LIMIT_DIGEST_KEY`; never commit them. Forwarded client-IP headers are
ignored by default, and network limiting is omitted rather than grouping all
clients into one denial-of-service-prone bucket. Set `TRUST_PROXY_HEADERS=true`
only when all traffic must pass through a trusted proxy that strips any inbound
`X-Lumina-Client-IP` header and sets exactly one validated client address.
`X-Forwarded-For` and `X-Real-IP` are never used by the application.

The LUM-002 identity migration creates only identity, RBAC, session-registry, recovery-grant, rate-limit, and audit tables. Applying it does not create a user or any credential. B2 adds no migration or bootstrap account. Future schema changes require an approved ERD and migration.

Stop the application with `Ctrl+C` and the local database with:

```sh
docker compose down
```

The named database volume is preserved. Removing it is destructive and is intentionally not part of normal setup.

## Commands

| Command                      | Purpose                                           |
| ---------------------------- | ------------------------------------------------- |
| `npm run dev`                | Start the Next.js development server              |
| `npm run build`              | Produce a production build                        |
| `npm run start`              | Serve a completed production build                |
| `npm run typecheck`          | Run strict TypeScript checks                      |
| `npm run lint`               | Run ESLint with warnings treated as failures      |
| `npm run format`             | Format supported files with Prettier              |
| `npm run format:check`       | Verify formatting without changing files          |
| `npm test`                   | Run Vitest unit tests once                        |
| `npm run test:watch`         | Run Vitest in watch mode                          |
| `npm run test:integration`   | Run PostgreSQL identity security tests            |
| `npm run prisma:generate`    | Generate the Prisma client                        |
| `npm run prisma:validate`    | Validate the Prisma schema and environment        |
| `npm run prisma:connect`     | Execute a read-only `SELECT 1` connectivity check |
| `npm run db:roles -- create` | Create/rotate local migrator and runtime roles    |
| `npm run db:roles -- grant`  | Apply least-privilege runtime table grants        |

## Browser smoke tests

Install the pinned package dependencies and Chromium once, then run the smoke suite:

```sh
npm ci
npx playwright install chromium
npm run test:e2e
```

Playwright starts the development server automatically. Its global fixture creates a random disposable account in the test database, exercises login, encrypted cookies, logout, CSRF denial and the protected dashboard, then deactivates the account and removes its credential, memberships and sessions. The retained random user identifier preserves append-only audit foreign keys. There is no application test-account endpoint or hardcoded credential.

## PostgreSQL integration tests

Use a disposable local database; the suite creates records and verifies denial constraints. Never point it at a shared or production database.

```sh
createdb lumina_identity_test
npm run db:roles -- create
DATABASE_URL="$MIGRATION_DATABASE_URL" npx prisma migrate deploy
npm run db:roles -- grant
TEST_DATABASE_URL="$DATABASE_URL" TEST_MIGRATION_DATABASE_URL="$MIGRATION_DATABASE_URL" npm run test:integration
```

Use only untracked local credentials. The test database name must be reflected in all three local URLs before configuring its roles. CI creates an ephemeral PostgreSQL service and validates separate migration-owner and least-privilege runtime credentials.

## Project structure

```text
prisma/                 ORM schema, migrations, and connectivity query
src/app/                Next.js routes and route composition
src/modules/foundation/ LUM-001 application-shell and health behaviour
src/modules/identity/   LUM-002 identity policy and persistence primitives
tests/e2e/               Browser smoke tests
tests/integration/       PostgreSQL integration and security tests
docs/                    Blueprint, decisions, and ticket specifications
```

Read [`src/modules/README.md`](src/modules/README.md) before adding a module. Architecture decisions and unresolved prerequisites are tracked in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Continuous integration

GitHub Actions uses Node 20 and an ephemeral PostgreSQL 17 service. It creates separate migration and runtime roles, applies migrations as the migration owner, applies explicit runtime grants, and runs privilege-denial integration tests. It then runs formatting, Prisma validation/generation, typecheck, lint, unit tests, build, and Chromium smoke tests. CI credentials are isolated placeholders and are not suitable for any external environment.
