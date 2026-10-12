# Module conventions

`src/modules` holds independently scoped parts of the modular monolith. LUM-001 creates only `foundation`, which owns the application shell and service health response. Do not create empty business-module folders merely to imply functionality.

For future approved tickets:

- Keep route composition in `src/app`; move module-specific UI and behaviour into the owning module.
- Separate UI components, validation schemas, application services, and persistence adapters when those layers exist.
- Keep business rules in server-side application services. Client visibility is never an authorization boundary.
- Put broadly reusable, domain-neutral infrastructure in `src/shared` only after there is a demonstrated cross-module use.
- Expose a small documented public surface from each module rather than importing its internal files across modules.
- Add tests beside units and use dedicated integration/e2e directories for boundary tests.
- Do not add domain tables without an approved ERD, migration, and ticket.
