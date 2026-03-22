---
name: review
description: Review current code changes against the library's conventions and patterns before handoff or merge. Use when asked to review changes, check work, or prepare for PR.
---

Review target: $ARGUMENTS

If no target is provided, review the current working diff (`git diff`).

## Goal

Catch convention violations, bugs, and quality issues before the developer commits and opens a PR.

## Procedure

### Step 1 — Collect Scope

- Run `git status` and `git diff` (staged + unstaged).
- If specific files are given as arguments, restrict scope to those.
- Identify which areas are touched (guards, decorators, services, proxy, token, interfaces).

### Step 2 — Convention Compliance

Check every changed file against the library's patterns:

| Area | What to check |
|---|---|
| **Guards** | Inject via `@Inject(KEYCLOAK_INSTANCE)` etc., use `ResolvedTenantConfig` (not Keycloak instances), use `useTenantConfig()` for tenant resolution, `extractRequest()` for request extraction |
| **Services** | `@Injectable()`, proper NestJS Logger usage, throw typed errors from `errors.ts` (not plain `Error`) |
| **Decorators** | Use `SetMetadata` from `@nestjs/common`, use local types (not `keycloak-connect` types) |
| **Errors** | All `throw` sites use the typed hierarchy from `errors.ts` (`KeycloakConfigError`, `KeycloakTokenError`, `KeycloakPermissionError`, `KeycloakAdminError`). Guards still throw NestJS `UnauthorizedException`/`ForbiddenException`. |
| **Token** | `hasRole()` matches three-form logic (`"role"`, `"realm:role"`, `"client:role"`) |
| **Interfaces** | Backward-compatible config fields, proper JSDoc |
| **Module** | New services registered as providers and exports in `keycloak-auth.module.ts` |
| **Exports** | New public types exported via `keycloak-auth.module.ts` and `src/index.ts` |

### Step 3 — Quality Checks

```bash
# TypeScript compilation
npm run build

# Lint
npm run lint
```

Verify:
- No `keycloak-connect` npm package imports remain in `src/`
- No plain `throw new Error(` in `src/` — all errors should use the typed hierarchy from `errors.ts`
- No unused imports (enforced by `eslint-plugin-unused-imports`)
- 3-space indentation, single quotes

### Step 4 — Security Quick Scan

Check for common issues:
- Token validation bypass paths
- Sensitive data in logs (secrets, full tokens)
- Hardcoded secrets or unsafe fallbacks
- Missing null checks on JWT parsing
- Proper error handling that doesn't leak internal details

### Step 5 — Output Format

```markdown
## Review Summary

**Scope:** [files reviewed]
**Status:** [Pass | Pass with notes | Needs changes]

### Findings

#### [High] Finding title
**File:** src/module/file.ts:42
**Issue:** What's wrong.
**Fix:** What to do.

#### [Medium] Finding title
...

#### [Low] Finding title
...

### Checklist
- [ ] `npm run build` passes
- [ ] `npm run lint` passes (0 errors)
- [ ] No `keycloak-connect` package imports in src/
- [ ] No security issues found

### Notes
[Any residual risks, areas not fully covered, or follow-up suggestions]
```

Severity definitions:
- **High**: bug, security hole, breaking API change, missing error handling
- **Medium**: convention deviation, maintainability risk
- **Low**: style suggestion, minor improvement, non-blocking note
