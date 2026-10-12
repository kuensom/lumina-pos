# Lumina POS — Instructions for Coding Agents

## Project and source of truth
- Product: Lumina POS, a cloud-hosted point-of-sale system for a shop in Thimphu, Bhutan.
- Read `docs/TECHNICAL_BLUEPRINT.md` and the assigned `docs/tickets/*.md` before editing.
- If requirements conflict, stop and report the ambiguity; do not silently invent business policy.
- Implement only the active ticket, on its own Git feature branch. Small reviewable changes are preferred.

## Design and code conventions
- Modular monolith. Next.js App Router, React, strict TypeScript; PostgreSQL; Prisma; Zod; Tailwind.
- Separate UI, validation, application services, persistence, and shared infrastructure.
- Keep business rules on the server; never treat hidden UI elements as security.
- Use schema migrations for every schema change. Get human approval before irreversible migrations.
- Do not change unrelated modules or add dependencies without explaining why.
- Prefer accessible responsive UI, keyboard navigation, and scanner-compatible inputs.

## Invariants for future tickets
- Retail and wholesale use the same stock ledger; movements must be auditable.
- Completed financial records and stock movements must not be silently deleted or overwritten.
- Use exact decimal / confirmed currency minor-unit representation; never floating-point money calculations.
- Payment evidence is not verified payment. Support explicit verification states.
- Use transactional operations, unique references and idempotency where sales/payments/imports could duplicate.
- Receipts must allow printed or digital presentation; receipt printing is not mandatory.
- Offline handling in V1 is controlled pre-numbered manual receipt entry/import, not automatic offline sync.
- Configurable role permissions and server-side permission enforcement are required.

## Security and operations
- Never create or commit secrets, credentials, production customer records or real payment data.
- Use `.env.example` with placeholders and ignore `.env*` except that example.
- No production data access, production deployments, force pushes, destructive commands or external paid services without explicit human approval.
- Log meaningful actions without sensitive data, and redact sensitive errors.
- Do not represent placeholder or mocked flows as working functionality.

## Quality gates and handoff
- Add or update tests for every implemented behaviour.
- Before completion run available typecheck, lint, tests and build; state honestly if unable to run them.
- Report: summary, changed files, migrations, commands and results, assumptions, limitations, risks, and manual review steps.
- Do not merge branches automatically; request review and approval.
