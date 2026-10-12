# Lumina POS — V1 Functional Scope and Technical Blueprint

**Version:** 1.0 (proposed baseline)  
**Date:** 12 October 2026  
**Location:** Thimphu, Bhutan  
**Delivery:** AI agent-assisted, modular monolith  
**Currency:** Bhutanese Ngultrum (BTN)

## 1. Objectives
Build a reliable, auditable, cloud-hosted POS for Lumina with shared retail/wholesale inventory, configurable rules, and controlled manual receipt recovery during outages. Build incrementally, starting with a usable retail checkout.

## 2. Release boundaries
### Release 1 — Retail operations
- Authentication, role-based access and user management
- Product, variant, category, brand and barcode management
- Opening stock, inventory receipts, adjustments and movement history
- Retail scan/search, cart, checkout, multi-method payment handling
- Printed receipt by default; optional non-mandatory printing and digital delivery
- Cash sessions, closing, reconciliation, audit trail and basic operational reports

### Release 2 — Complete V1
- Customer membership, points and redemption
- Wholesale customer accounts, orders, invoices, partial/deferred payments and due dates
- Payment evidence, verification, failed-verification exceptions and follow-up workflow
- Configurable notification channels (enabled/disabled by administrators)
- Retail exchange-only policy, configurable eligibility, separate wholesale returns
- Configurable discounts, thresholds, exclusions and eligibility periods
- Pre-numbered offline handwritten receipt recovery via entry or spreadsheet import
- Dashboards, payment aging, inventory reports and P&L/accounting summaries
- Administration and business rules configuration

## 3. Non-goals for initial V1
- Fully offline synchronising browser POS
- Microservice architecture
- Multiple branches, multi-currency and advanced procurement (unless subsequently approved)
- Direct bank/payment-provider settlement integration until feasibility is evaluated
- Production tax/accounting compliance assumed without local professional validation

## 4. Architecture
Modular monolith with Next.js App Router, React, TypeScript, Tailwind CSS, shadcn/ui, PostgreSQL, Prisma, Zod, Vitest, Playwright, GitHub, Docker and managed deployment. Organise business logic in independently scoped modules with shared infrastructure. Use server-side permission checks and transactional application services.

### Logical modules
`auth`, `users`, `roles`, `products`, `inventory`, `retail`, `receipts`, `payments`, `customers`, `loyalty`, `wholesale`, `returns`, `discounts`, `cash-management`, `reconciliation`, `notifications`, `reports`, `administration`, `audit`.

## 5. Domain design rules
1. Retail and wholesale draw from the same product variant and stock ledger.
2. Use append-only stock movements and explicit reversal/correction records; never silently overwrite historical movements.
3. Committed financial transactions are not hard-deleted. Use controlled void/reversal workflows with reason, actor and time.
4. Store money as integer minor units (after confirming BTN precision) or exact SQL decimal; never use binary float for money.
5. A sale, associated payment, stock movement and receipt reference must be committed atomically as applicable.
6. Add uniqueness/idempotency controls for payment submissions, sale checkout and offline receipt import.
7. Record verification independently from proof of payment: evidence submitted is not the same as a settled payment.
8. Every protected mutation requires authentication, permission checks, validation and audit coverage.
9. Use explicit status transitions for retail sale, wholesale invoice, payment verification, returns and notification follow-up.
10. Report financial summaries consistently with payment, returns, cash and accounting definitions that have been approved.

## 6. Preliminary data entities
- Identity: User, Role, Permission, RolePermission, UserRole, AuditEvent
- Catalogue: Category, Brand, Product, ProductVariant, Barcode, PriceHistory
- Inventory: InventoryBalance, StockMovement, OpeningStockBatch, StockAdjustment
- Retail: RetailSale, RetailSaleLine, RetailPayment, Receipt, CashSession, CashMovement, CashReconciliation
- Customers & loyalty: Customer, Member, LoyaltyAccount, LoyaltyLedger, LoyaltyRule
- Wholesale: WholesaleCustomer, WholesaleOrder, WholesaleOrderLine, WholesaleInvoice, PaymentAllocation, PaymentEvidence, PaymentVerification, PaymentFollowUp
- Commercial policy: DiscountRule, DiscountExclusion, ReturnRequest, ReturnLine, ExchangeTransaction
- Operations: OfflineReceiptRegister, OfflineReceiptImport, NotificationPreference, NotificationAttempt, SystemSetting

*This is a logical entity inventory, not the final relational schema. Cardinality, data constraints and naming will be established in the ERD step.*

## 7. Roles and permissions
Seed proposed roles: Administrator, Supervisor, Cashier. Role names are defaults; permissions must be configurable. Wholesale functions are permission-gated to owner/supervisors per original requirements. Apply least privilege server-side.

## 8. Quality requirements
- Security: least privilege, secure credentials/sessions, encryption in transit, audit logs, secrets managed outside source control
- Reliability: transactional writes, recoverability, backup and restore drills, idempotent transaction handling
- Operability: logging, error monitoring, deployment rollback plan
- Usability: keyboard/scanner-friendly checkout, clear error states, receipt reissue traceability
- Testing: unit tests, service integration tests, e2e scenarios, permissions and transaction race tests

## 9. Implementation order
1. Repository/bootstrap and quality gates
2. Identity and permission framework
3. Product catalogue and barcode
4. Opening stock and stock ledger
5. Retail checkout + payment + receipt
6. Cash management and first pilot
7. Customers and loyalty
8. Wholesale, invoices, partial payments and verification
9. Follow-up workflow and notifications
10. Returns, discounts and offline receipt recovery
11. Reporting, P&L, configuration and V1 hardening

## 10. Agent operating rules
- Read requirements and architecture documents before implementing.
- Work on one approved ticket and one branch at a time.
- Describe proposed changes before implementation when they affect schema or public interfaces.
- Make migrations for schema changes and include rollback planning.
- Preserve existing business rules and interfaces; do not invent new functionality.
- Add tests and report command results before requesting review.
- Never expose credentials in source code or logs.
- Never alter production data, payment state or financial records without explicit approval.
- Report files changed, tests run, remaining issues and known assumptions.

## 11. First agent task: repository foundation
**Goal:** Set up a working application skeleton without implementing POS transaction logic.

**Acceptance criteria:**
- Next.js TypeScript project with strict compilation, ESLint and formatting
- App shell: login placeholder, dashboard placeholder, navigation placeholders
- Modular `src/modules` structure and documented coding conventions
- PostgreSQL local Docker configuration and ORM initialisation
- Sample environment template (no secrets)
- Automated CI for typecheck, lint and tests
- Smoke test for home page and basic health endpoint
- README with local setup and commands
- Changes limited to repository foundation; no fabricated checkout logic

## 12. Decisions to validate before implementation
1. Target device(s), receipt printer, barcode scanner and label printer compatibility.
2. Exact payment capture methods and whether external gateway integration is required.
3. Digital receipt channels (email/SMS/messaging) and provider availability in Bhutan.
4. BTN rounding/precision, receipt numbering and Bhutan tax/accounting obligations.
5. Opening-stock import template, product variant dimensions and barcode scheme.
6. Hosting location, backups, recovery targets and data-retention requirements.
7. Offline manual receipt custody, uniqueness and duplicate import policy.

## 13. Next deliverable
Detailed domain ERD and data dictionary, starting with identity, catalogue and inventory; then create the repository and execute the first agent ticket.
