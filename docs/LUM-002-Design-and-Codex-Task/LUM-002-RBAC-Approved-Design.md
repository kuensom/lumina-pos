# Lumina POS — LUM-002 Identity and RBAC Design Baseline

Version 1.1 | 12 October 2026 | Status: Product decisions approved; technical architecture pending approval

## Approved decisions

1. Staff sign in using either a username or an email address plus a password.
2. Username is mandatory and unique, ignoring case. Email is optional and unique when provided, ignoring case. No public self-registration.
3. Password recovery is **administrator-assisted**. No outbound email/SMS password-reset integration in LUM-002.
4. One staff member may have multiple active roles. Permissions are server-enforced and deny-by-default.
5. Staff accounts are provisioned by authorised administration, with no hard-coded default credentials.

## Administrator-assisted recovery — approved business policy

- An authorised administrator initiates a reset only after verifying the staff member's identity through a documented in-person/organisational process.
- Do not disclose existing passwords or set a permanent password on behalf of staff.
- Issue a short-lived, single-use, cryptographically random reset/enrolment secret, stored **only as a digest**. The staff member chooses their own new password through a protected setup flow.
- Deliver the one-time secret using an approved private channel; never expose it in general audit records, logs, repository files or persistent admin lists.
- The password-reset action must revoke existing sessions (or invalidate them by server-enforced session version), be rate-limited where relevant, and produce an audit event without secrets.
- Require password setup before first normal login for new accounts; a reset or bootstrap process must not create an indefinite reusable credential.
- Recovery authorisation should be limited to approved privileged roles; ordinary admins must not reset a Super Administrator without a separate protected recovery procedure.
- Codex must propose practical token delivery/custody mechanics and protect against shoulder-surfing or replay. Product owner approves that detail before implementation.

## Identity / schema requirements

User: id, mandatory username, usernameNormalized (unique), optional email, emailNormalized (unique when nonnull), displayName, passwordHash or library-equivalent credential, status, authzVersion, timestamps.
Role: id, immutable unique code, name, description, isSystemRole, isActive, timestamps.
Permission: id, immutable unique `resource:action` code, description, resource, action.
UserRole: unique (userId, roleId), assignment metadata.
RolePermission: unique (roleId, permissionId).
Session: associated user, expiration, server-side revocation / version enforcement, hashed opaque session identifier if using database sessions.
PasswordReset: userId, hashed token, expiry, single-use consumed timestamp, requestedBy; avoid storing raw token.
AuditEvent: immutable event identity, nullable actor, type, target, outcome, redacted metadata, timestamp.
Auth-library adapter models may be added only if justified. All FK deletion rules and indexes must be proposed in the ERD before migrations.

## Initial permission matrix

Permissions: dashboard:view; users:read/create/update/deactivate; roles:read/create/update/assign; permissions:read/assign; audit:read.

- Super Administrator: all LUM-002 permissions; additional guard for granting super-admin or changing critical configuration.
- Administrator: dashboard:view; users:read/create/update/deactivate for non-super-admin accounts; roles:read/assign (non-privileged roles); permissions:read; audit:read limited to staff administrative events.
- Supervisor: dashboard:view; users:read limited to minimum staff directory.
- Cashier / Sales Staff: dashboard:view.
- Wholesale Sales Staff: dashboard:view.
  Reserved future permissions do not create functioning sales/stock/wholesale endpoints.

## Security invariants

- Distinguish authentication from authorisation; check protected reads and mutations on the server.
- No privilege escalation through crafted requests or the union of assigned roles. Enforce special-role protections outside the ordinary configurable permission list.
- Prevent deactivating/removing the last active Super Administrator under concurrent requests inside a database transaction.
- Deactivation, password reset and role changes must terminate or immediately restrict affected sessions.
- Passwords use reputable password hashing; never persist plaintext/reversible passwords; generic login errors and rate limiting.
- Secure HttpOnly cookies, CSRF protection appropriate to the chosen auth library, safe redirects, audit events without secrets.
- Initial Super Administrator creation must be a one-time controlled bootstrap procedure, never a committed default password.
- No real customer data, payments, retail operations, inventory or production deployment in LUM-002.

## Acceptance tests

1. Username/password login and optional email/password login for same user.
2. Case-insensitive uniqueness; nullable email permits multiple users without email.
3. Generic error for nonexistent account / wrong password / inactive account.
4. Direct API requests cannot bypass server-side RBAC.
5. Admin creates ordinary staff, assigns allowed roles, and cannot grant themselves or anyone a super-admin role.
6. Last active Super Administrator cannot be deactivated or lose protective role, including concurrent requests.
7. Password recovery initiated by allowed admin only after identity verification procedure; reset token is one-use and expires.
8. Reset never exposes secret in audits; password set by staff; previous sessions revoked.
9. Logout invalidates session; deactivated user denied subsequent requests.
10. Typecheck, lint, unit, Postgres integration, end-to-end browser tests and production build pass.

## Decisions awaiting approval before coding

- MFA policy: recommended mandatory for Super Administrator before production.
- Session policy: proposed 30-minute idle timeout, 12-hour absolute lifetime, allow multiple devices with global revocation.
- Username format: proposed 3–32 ASCII characters [a-z0-9._-], case-insensitive.
- Token delivery and verification procedure in administrator-assisted reset.
- Auth library, maintained versions, adapter/schema details, and migration/rollback approach.
- Scope/visibility of admin audit records.
- Whether step-up authentication for super-admin privilege assignment is implemented in LUM-002 or held for a separate preproduction gate.

## Gate

This document is a product requirements baseline. Codex's next task is design-only: no code, database migration, commits, deployment or merge without review of its architecture proposal.
