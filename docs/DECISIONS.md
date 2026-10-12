# Architecture decisions and open prerequisites

## LUM-001 decisions

### Runtime and dependency policy

- Node.js 20 LTS (`>=20.9.0`) and npm 10 or newer are the supported local and CI toolchain.
- Direct and development dependencies are exact-pinned. `npm ci` with the committed lockfile is the reproducible install path.
- Next.js App Router and strict TypeScript provide the application boundary; Tailwind supplies only the accessible base presentation needed by this ticket.

### Application boundaries

- `src/app` owns routing and composition.
- `src/modules/foundation` is the only initial module. It owns the shell and deterministic health payload.
- `/login` is visibly and technically disabled. Authentication and permissions remain LUM-002 work.
- `/api/health` reports process-level application availability only. It does not claim database readiness.

### Data foundation

- PostgreSQL 17 runs locally through Docker Compose with environment-provided developer credentials and a named persistent volume.
- Prisma is configured for PostgreSQL but deliberately has no models or migration. `prisma db execute` with `SELECT 1` is the non-mutating connectivity check.
- No production database, secret manager, deployment target, backup policy, or operational schema is configured by this ticket.

### Automated checks

- Vitest checks deterministic foundation behaviour.
- Playwright verifies user-visible dashboard and login placeholders plus the health endpoint in Chromium.
- CI runs format, generated-client/schema validation, typecheck, lint, unit tests, build, and browser smoke tests without production secrets.

## Unresolved prerequisites for future tickets

These blueprint decisions remain deliberately unresolved and must be approved before dependent implementation:

1. Target checkout hardware and receipt, barcode, and label-printer compatibility.
2. Payment capture methods and any external gateway feasibility.
3. Available digital receipt channels and providers in Bhutan.
4. BTN precision and rounding, receipt numbering, and local tax/accounting obligations.
5. Opening-stock import format, variant dimensions, and barcode scheme.
6. Hosting region, backup/restore targets, retention, monitoring, and recovery objectives.
7. Manual receipt custody, uniqueness, and duplicate-import policy.
8. The identity, catalogue, and inventory ERD and data dictionary before any business models or migrations are created.
