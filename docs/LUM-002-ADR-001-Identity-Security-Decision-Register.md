# ADR-001 — LUM-002 Identity, RBAC and Security Decision Register

**Project:** Lumina POS  
**Status:** Product-policy decisions approved; B1 implementation **not yet authorised**  
**Date:** 2026-10-13  
**Source architecture:** LUM-002-A1 Refined Authentication and RBAC Architecture; existing LUM-002 design baseline.

## 1. Approved decisions

| ID      | Subject                                 | Approved decision                                                                                                                           | Required architecture update                                                                                                                            |
| ------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SEC-001 | Staff identification                    | Username or optional email plus password; unique case-insensitive identifiers; no public signup                                             | Retain `usernameNormalized`, nullable unique `emailNormalized`, generic failed-login errors.                                                            |
| SEC-002 | Staff password recovery                 | Administrator-assisted, identity verified, single-use token and staff-chosen new password                                                   | No mandatory staff email, no reusable or administrator-known passwords.                                                                                 |
| SEC-003 | MFA                                     | MFA mandatory for Super Administrators **before production**, with the specific method still undecided                                      | Explicit preproduction release gate; do not claim MFA implemented in B1.                                                                                |
| SEC-004 | Idle timeout                            | **60 minutes** since last eligible authenticated activity                                                                                   | Replace all 30-minute assumptions in design, test fixtures and session validation/refresh SQL.                                                          |
| SEC-005 | Absolute timeout                        | **12 hours** from original sign-in (existing proposed default, retained pending product confirmation if not previously explicitly accepted) | Must never be extended by cookie/JWT refresh.                                                                                                           |
| SEC-006 | Username modifications                  | **Super Administrator only**, with audit                                                                                                    | Permit exceptional audited changes; validate format, unique normalized username, revocation of existing sessions, and no ordinary-admin edits.          |
| SEC-007 | Sole Super Administrator recovery       | Documented emergency break-glass procedure with **independent approval**                                                                    | No ordinary-admin override; separate elevated runbook, evidence of independent approval, high-severity immutable audit and credential/session rotation. |
| SEC-008 | RBAC                                    | Multiple active roles; deny-by-default server-side permissions and immutable protected capabilities                                         | Prevent privilege escalation via reconfigured roles; invalidate affected users on permission/role changes.                                              |
| SEC-009 | Staff and Super Administrator passwords | Secure Argon2id hashing; no committed defaults                                                                                              | Implementation choice still requires Node 20/native build and npm audit verification.                                                                   |

**Clarification:** SEC-005 is recorded as a retained design default, not a newly expressed approval. Any conflict between this ADR and the earlier refined proposal is resolved in favor of the user's explicit decisions above.

## 2. B1 blockers — resolve before writing migrations or changing dependencies

1. **Authentication stack approval and compatibility proof:** Verify the exact versions of `next-auth@4.24.15` and `@node-rs/argon2@2.2.2` against the repository's actual Next.js, React, Node 20 and dependency set; demonstrate installation and native load under Node 20. A temporary package-graph audit under Node 16 is not sufficient. Because B1 does not implement authentication endpoints, defer installing NextAuth to B2 unless B1 has a concrete verified dependency on it.
2. **Final Prisma schema / SQL mapping:** Review tables, indexes, nullable email uniqueness, foreign keys, deletion rules, immutable system permissions, append-only audit restrictions and SQL column naming. Migration must run against a disposable Postgres instance, never a production database.
3. **Database access model:** Decide how to provision separate migration-owner and runtime DB roles in Docker/local CI and deployment, ensuring runtime audit INSERT/SELECT but not UPDATE/DELETE. Provide tests that verify the restriction.
4. **Permission catalog and protected invariants:** Specify canonical protected permission IDs and role codes; freeze `requiresSuperAdmin` classification. Define catalog seeding and upgrade behavior when definitions evolve.
5. **B1 scope and acceptance gate:** B1 consists of schema/migration, constraints, seed catalog, hashing/normalization/digest utilities and integration tests. No login, password recovery, bootstrap UI, JWT cookie, MFA, real accounts, or production deployment. Obtain approval of the exact B1 task before coding.
6. **Username update representation:** The schema can support username edits; define a safe update service contract and audit event, but implement the privileged update endpoint only after B2/B3 authentication and RBAC enforcement exist. Do not add an unauthenticated username-editing path in B1.

## 3. Requirements that are not B1 blockers, but MUST be resolved before relevant later slices or production

- Choose MFA mechanism, enrollment, step-up verification and recovery-code custody before implementing privileged actions or deploying to production.
- Define and approve the independent break-glass approver(s), evidence, custody, emergency execution and post-incident review. A checkbox alone does not constitute independent approval.
- Establish staff identity-verification evidence standards for administrator-assisted reset, one-time secret handover and 15-minute expiry.
- Confirm 12-hour absolute session limit, permitted devices, 5-minute recent-authentication window and password policy (previously proposed: 12–128 characters).
- Define precisely which audit events ordinary administrators can read; implement server-side filtered projections.
- Determine audit retention with legal/privacy review; a seven-year period is a proposal, **not a confirmed Bhutanese legal requirement**.
- Select hosting, trusted-proxy/IP policy, HTTPS/cookies, secret management, rotation and backup/restore procedures before production.
- Complete protected-role escalation controls, concurrency-safe last-super-admin checks, atomic reset consumption, MFA, end-to-end negative authorization tests and recovery rehearsals before production.

## 4. B1 exit criteria

- Node 20/npm 10 environment confirmed; baseline and new dependencies audited (full and production scopes) with changes recorded.
- Prisma generation and validation pass; reviewed migration applies to an empty ephemeral PostgreSQL database with checks and indexes verified.
- Repeated seed execution is idempotent and protected capabilities cannot be rewritten.
- Case-insensitive username and nullable email uniqueness tests pass.
- Password/token tests verify Argon2id, secret digests, no plaintext storage and no raw secrets in logs.
- Audit rows are append-only for runtime credentials and database access privileges are tested.
- No unauthenticated live administration or reset actions introduced.
- `npm run format:check`, typecheck, lint, unit/integration tests and production build pass; GitHub CI green.
- Code and migration undergo human/assistant review before merge; B1 must not be merged automatically.

## 5. Codex pre-implementation instruction (design/validation only)

> Read AGENTS.md, the LUM-002-A1 refined proposal, and this ADR. Reconcile all conflicting session references to **60-minute idle / 12-hour absolute (subject to confirmation)**. Update the username policy so only a Super Administrator may change a username, with audit and session invalidation. Preserve MFA as mandatory before production, with mechanism open, and define independently approved sole-Super-Administrator break-glass recovery. Produce a final B1-specific schema/migration plan, catalog-seeding plan, local/CI database privilege model, pinned-dependency test plan under Node 20, and acceptance-test matrix. Flag every unresolved prerequisite. **Do not modify application code, install dependencies, create migrations, commit or merge. Stop for review and explicit B1 authorisation.**
