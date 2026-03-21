# AGENTS.md

## Project Purpose

`nestjs-keycloak-auth` is a self-contained, bearer-only NestJS library for Keycloak authentication
and authorization. It provides guards, decorators, and services for JWT validation, role checks, and
UMA-based resource authorization. Endpoints are resolved via OIDC discovery
(`.well-known/openid-configuration`) with no runtime dependency on `keycloak-connect`.

## Current Scope

- Bearer-token API/server flows only.
- OIDC discovery for endpoint resolution (token, introspection, JWKS, userinfo).
- ONLINE (introspection) and OFFLINE (JWKS signature) token validation.
- Multi-tenant realm resolution and per-realm revocation (`notBefore`) state.
- Admin callback support for `POST /k_push_not_before`.
- No browser/session middleware flows (login redirects, session/cookie stores, logout endpoints).

## Core Stack

- NestJS (library package)
- TypeScript
- `@nestjs/axios` + `axios` for outbound calls to Keycloak
- Node.js native `crypto` for token signature verification

## Architecture

### Module Structure

```
src/
  keycloak-auth.module.ts      # Dynamic module registration
  keycloak-auth.providers.ts   # Config parsing + ResolvedTenantConfig providers
  internal.util.ts                # Request extraction + tenant resolution helpers
  constants.ts                    # Injection tokens + enums
  util.ts                         # JWT payload parsing utility
  index.ts                        # Package public entry

  controllers/
    keycloak-admin.controller.ts  # POST /k_push_not_before admin callback

  token/
    keycloak-token.ts             # Token parser/helpers (roles, permissions, expiry)
    keycloak-grant.ts             # Access-token-focused grant model

  services/
    oidc-discovery.service.ts     # OIDC .well-known endpoint discovery + cache
    keycloak-http.service.ts      # Keycloak endpoint HTTP operations (uses discovered URLs)
    keycloak-grant.service.ts     # Grant creation + offline validation pre-check
    token-validation.service.ts   # Online/offline validation + per-realm notBefore cache
    keycloak-multitenant.service.ts # Tenant config resolution + cache
    jwks-cache.service.ts         # JWKS retrieval/cache and key lookup
    keycloak-url.service.ts       # URL helper exports

  guards/
    auth.guard.ts                 # Authentication guard
    resource.guard.ts             # UMA resource/scope enforcement
    role.guard.ts                 # Role enforcement

  decorators/                     # @Public, @Roles, @Resource, @Scopes, etc.
  interface/                      # Config, tenant, JWKS, grant, enforcer option types
```

### Key Design Decisions

- No `keycloak-connect` runtime dependency.
- OIDC discovery (`OidcDiscoveryService`) resolves endpoints from `.well-known/openid-configuration` with a 5-minute cache per realm and Keycloak-path fallbacks.
- `ResolvedTenantConfig` is used instead of Keycloak instance objects.
- `TokenValidationService` stores `notBefore` per realm URL to avoid cross-realm revocation leakage.
- `ResourceGuard` sends default claims (`http.uri`, `user.agent`) when no custom `@EnforcerOptions()` claims are set.
- `AuthGuard` ONLINE path performs `createGrant()` pre-check before introspection for adapter parity.

## Workflow

### Verification Before Done

- Run `npm run build` after code changes.
- Run `npm run lint` before handoff.
- Ensure no accidental `keycloak-connect` runtime import is introduced in `src/`.
- Verify all Keycloak HTTP calls use `OidcDiscoveryService` rather than hardcoded endpoint paths.

### Git Rules

- Do not run `git commit` or `git push` automatically.
- Read-only git commands are fine (`git status`, `git diff`, `git log`).
- Developer reviews and performs commit/push manually.

## Code Conventions

- 3-space indentation.
- Single quotes.
- Max line length: 120 characters.
- Pre-commit hook uses `lint-staged` (Prettier + ESLint on staged `.ts` files).
- `any` may appear in request/dynamic boundaries when needed.

## AI Agent Skills

Project-level skills for Claude Code and Codex live under `.claude/skills/`.

```bash
# macOS / Linux
bash scripts/setup-codex-skills.sh

# Windows (PowerShell)
pwsh -File scripts/setup-codex-skills.ps1
```

Use an existing skill when directly relevant.

| Skill | Purpose |
|---|---|
| `review` | Review changes against conventions before handoff |
| `handoff` | Generate a handoff document |
| `sort-imports` | Sort TypeScript imports by line length |
| `typescript-review` | Strict review for TS/NestJS changes |
| `security-audit` | Security-focused audit for auth code |

## Key Commands

```bash
npm run build
npm run lint
npm run format
npm run clean
npm run release
```

## Key Files

- Module entry: `src/keycloak-auth.module.ts`
- Public API: `src/index.ts`
- Auth guard: `src/guards/auth.guard.ts`
- Resource guard: `src/guards/resource.guard.ts`
- Admin callback controller: `src/controllers/keycloak-admin.controller.ts`
- Token validation: `src/services/token-validation.service.ts`
- Package config: `package.json`
