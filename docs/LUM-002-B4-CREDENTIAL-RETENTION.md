# LUM-002-B4 credential data retention categories

This milestone does not select permanent retention periods. Operations and privacy review must approve them before production.

- Grant rows: security evidence containing digests and lifecycle timestamps; retain for a policy-approved investigation window.
- Delivery rows: operational status and redacted provider identifiers; retain only as long as delivery support and security investigation require.
- Encrypted outbox ciphertext: delete immediately after accepted delivery, terminal failure, revocation, or expiry. It is never general audit history.
- Rate-limit buckets: short-lived abuse-control state; purge after its review window.
- Audit events: immutable security records governed by the separate audit-retention policy. B4 adds no automatic deletion.

No category may contain a password, plaintext grant, complete invitation URL, raw IP address, provider credential, or identity-document data.

An in-person voucher is revealed once and then explicitly dismissed from active
UI state. Navigation also disposes it, and credential pages are not cached.
Software cannot prevent an administrator who has seen the voucher from copying,
photographing, or otherwise recording it outside the system; identity checks,
staff training, short expiry, single-use consumption, and audit review remain
necessary controls.

An ambiguous email-provider result is retained as `UNKNOWN` and is not
automatically redispatched. The encrypted payload remains only until expiry so
an approved reconciliation process can resolve the stable provider idempotency
key without creating duplicate invitations.

An expired `CLAIMED` delivery is also `UNKNOWN`: claim timeout does not prove
that the provider did not accept the request. Automated workers must never
redispatch it. Reconciliation is an explicit operational boundary requiring an
approved provider lookup by the stable delivery idempotency key. Production
provider execution remains disabled until that worker/provider contract and
the reconciliation procedure are approved. Expiry cleanup destroys ciphertext
even when reconciliation has not resolved the provider outcome.

Credential redemption admits five attempts per token in each fixed 15-minute
window; the sixth and subsequent attempts are rejected without increasing the
token counter. The existing trusted-network bucket admits at most 30 attempts
per 15-minute window. Credential-consumption buckets are retained for at most
two windows by opportunistic cleanup, counters are capped at their admission
limits, and public failures remain generic. Arbitrary unknown credentials share
one opaque bucket per window so attacker-controlled inputs cannot create an
unbounded number of database rows; issued credentials retain independent
per-token admission buckets.
