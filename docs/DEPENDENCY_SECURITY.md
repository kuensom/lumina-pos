# Dependency security notes

## LUM-001-S01 remediation

The foundation keeps exact direct dependency pins. Security updates in this ticket are intentionally limited to compatible patches and one targeted transitive override:

- `vitest` and `@vitest/coverage-v8` are kept on the 3.x line and updated together because the coverage package requires the exact matching Vitest version.
- Direct `postcss` is updated within the 8.x line.
- The `postcss` override matches the exact direct PostCSS 8.5.23 pin. This keeps every PostCSS consumer on that patched version, including Next.js 15.5.27, which otherwise pins vulnerable PostCSS 8.4.31 exactly. The override does not introduce a second version or cross a PostCSS major; typecheck, lint, production build, unit tests, and browser tests validate it.

Do not broaden the override to unrelated packages. Remove it when a supported Next.js 15 patch includes a non-vulnerable PostCSS version or after an approved Next.js major upgrade.

## Deferred major-upgrade proposals

The following development-only advisory chains have no complete compatible fix on the current major versions:

- Tailwind CSS 3 depends on the affected `chokidar`/`fast-glob`/`micromatch`/`braces` and selector-parser chain. Tailwind CSS 4 requires configuration and stylesheet migration and must be handled as a separately approved major upgrade.
- Any Vitest advisory remaining after the 3.2.7 patch requires evaluation of Vitest 4.1.11 or newer. A Vitest major upgrade must be approved and tested separately.
- Any ESLint chain remaining through `eslint-config-next` requires a coordinated supported Next.js/ESLint configuration upgrade rather than a downgrade to the audit tool's suggested Next 14 package.

Production and development findings must be reviewed separately. Development-only tooling is not shipped with the production application, but it still runs trusted repository content in local and CI environments and should be upgraded through controlled follow-up work.
