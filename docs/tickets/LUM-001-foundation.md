# LUM-001 — Repository and Application Foundation

**State:** Ready for agent implementation (approval to execute required)
**Branch:** `feature/LUM-001-foundation`

## Goal
Create a runnable, testable Next.js foundation for Lumina POS. No operational POS transactions or domain schema yet.

## Approved stack
- Next.js App Router, React, TypeScript strict mode
- Tailwind CSS, accessible base components (shadcn/ui only if compatible)
- PostgreSQL via local Docker Compose
- Prisma with compatible pinned versions
- Zod, Vitest, Playwright, ESLint, formatter
- npm for this initial setup; document version constraints

## Deliverables
1. App scaffold with `/` landing/dashboard placeholder and `/login` UI placeholder clearly labelled nonfunctional. No simulated sign-in success.
2. Modular `src/modules` folders documented with ownership conventions; add only minimal foundation modules, not empty fake business implementations.
3. Local Docker Compose PostgreSQL instance; health checks, persistent volume, no hard-coded production credentials; developer-only credentials via environment variables.
4. Prisma bootstrap and connectivity instructions; no business-domain schema tables. If a smoke-check is necessary use a safe connectivity mechanism.
5. `.env.example`, `.gitignore`, README containing exact prerequisites and commands for first run.
6. Scripts for dev, build, typecheck, lint, formatting check and unit tests; a minimal smoke test and optional health endpoint.
7. GitHub Actions CI to install dependencies and run checks; ensure CI does not require production secrets.
8. Basic Playwright browser smoke test with documented browser install steps.
9. Summarise architecture decisions and unresolved prerequisites in `docs/DECISIONS.md`.

## Acceptance criteria
- `npm install` (or `npm ci` when lockfile exists) succeeds with pinned and compatible dependencies.
- `npm run dev` serves the placeholder UI.
- `npm run typecheck`, `npm run lint`, `npm test`, and `npm run build` pass.
- Local database starts by `docker compose up -d`; Prisma can connect with local environment variables.
- Unit and browser smoke tests are meaningful and reproducible; browser test run is documented.
- No actual credentials are committed. `.env.example` contains placeholders only.
- No Sale, Inventory, Payment, Loyalty or Wholesale operational logic is implemented.
- Agent submits files changed, actual command outputs/results, risks and remaining questions.

## Out of scope
- Functional login and roles (LUM-002)
- Business database tables and ERD (requires approval before schema generation)
- Checkout, payment capture, barcode device integration, messaging or production deployment

## Agent execution prompt
Implement ticket `docs/tickets/LUM-001-foundation.md` according to `AGENTS.md` and `docs/TECHNICAL_BLUEPRINT.md`.
First inspect the repository and outline a concise implementation plan. Work only on branch `feature/LUM-001-foundation`.
Create the project foundation, verify all acceptance criteria, and provide a factual completion report listing commands run and their outcomes.
Do not create actual business tables, authentication claims, or production infrastructure.
Stop and ask for human approval before any destructive operation or unapproved major dependency change. Do not merge.
