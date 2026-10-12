# Lumina POS

Lumina POS is a planned cloud-hosted point-of-sale system for a shop in Thimphu, Bhutan. This repository currently contains the LUM-001 application foundation only. It does not provide working authentication, checkout, payments, inventory operations, or production infrastructure.

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
npm run prisma:connect
npm run dev
```

Open <http://localhost:3000>. The health endpoint is available at <http://localhost:3000/api/health>.

The `.env.example` values are placeholders for local development. Replace the password in your untracked `.env`; do not reuse it outside local development. Keep `POSTGRES_*` and `DATABASE_URL` aligned.

No migration is expected for LUM-001 because the Prisma schema intentionally contains no domain models. Future schema changes require an approved ERD and migration.

Stop the application with `Ctrl+C` and the local database with:

```sh
docker compose down
```

The named database volume is preserved. Removing it is destructive and is intentionally not part of normal setup.

## Commands

| Command                   | Purpose                                           |
| ------------------------- | ------------------------------------------------- |
| `npm run dev`             | Start the Next.js development server              |
| `npm run build`           | Produce a production build                        |
| `npm run start`           | Serve a completed production build                |
| `npm run typecheck`       | Run strict TypeScript checks                      |
| `npm run lint`            | Run ESLint with warnings treated as failures      |
| `npm run format`          | Format supported files with Prettier              |
| `npm run format:check`    | Verify formatting without changing files          |
| `npm test`                | Run Vitest unit tests once                        |
| `npm run test:watch`      | Run Vitest in watch mode                          |
| `npm run prisma:generate` | Generate the Prisma client                        |
| `npm run prisma:validate` | Validate the Prisma schema and environment        |
| `npm run prisma:connect`  | Execute a read-only `SELECT 1` connectivity check |

## Browser smoke tests

Install the pinned package dependencies and Chromium once, then run the smoke suite:

```sh
npm ci
npx playwright install chromium
npm run test:e2e
```

Playwright starts the development server automatically. The suite checks the dashboard placeholder, the explicitly disabled login placeholder, and the health endpoint.

## Project structure

```text
prisma/                 Empty ORM bootstrap and connectivity query
src/app/                Next.js routes and route composition
src/modules/foundation/ LUM-001 application-shell and health behaviour
tests/e2e/               Browser smoke tests
docs/                    Blueprint, decisions, and ticket specifications
```

Read [`src/modules/README.md`](src/modules/README.md) before adding a module. Architecture decisions and unresolved prerequisites are tracked in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Continuous integration

GitHub Actions uses Node 20 and runs install, formatting, Prisma generation and validation, typecheck, lint, unit tests, build, and Chromium smoke tests. It supplies only a placeholder-format `DATABASE_URL`; CI does not need a running database because LUM-001 has no integration test or model migration.
