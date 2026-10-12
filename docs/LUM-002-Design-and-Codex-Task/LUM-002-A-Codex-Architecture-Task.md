# LUM-002-A — Codex Architecture Review (DESIGN ONLY)
Read AGENTS.md, docs/TECHNICAL_BLUEPRINT.md, docs/DECISIONS.md and docs/LUM-002-RBAC-Approved-Design.md.

Approved requirements:
- Login by username OR optional email, plus password; no public registration.
- **Administrator-assisted password recovery**, without email/SMS provider.
- Staff member must create their own password through a one-time, short-lived, hashed reset secret.
- Reset and role/deactivation changes revoke or immediately restrict existing sessions.

Produce:
1. Auth library shortlist, final recommendation, maintained compatible versions for currently pinned Next.js/React/Prisma, and reasoned tradeoffs.
2. Exact proposed Prisma schema, field types, unique constraints, FKs, delete behavior and indexes for Users, Roles, Permissions, memberships, Sessions, recovery tokens and AuditEvents.
3. Account bootstrap and administrator-assisted recovery workflow with token delivery and verification, password hashing, revocation, audit redaction and reset replay prevention.
4. LUM-002 role-permission matrix, default-deny API guards, super-admin protection and race-safe last-super-admin enforcement.
5. Login/logout/recovery routes and page plan; rate-limiting and CSRF/session controls.
6. Unit, PostgreSQL integration, negative-authorisation and Playwright test cases, plus manual acceptance script.
7. Differences from approved baseline, unresolved decisions (MFA, timeout, username format, protected recovery), migration/rollback plan and dependency security implications.

**Do not write or modify application code, migrations, secrets, Git commits, branches or pull requests.**
Return the proposed architecture and schema in the Codex response and STOP for review.
