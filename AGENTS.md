# AGENTS.md

## Project Purpose

`nestjs-keycloak-auth` — a self-contained NestJS library for Keycloak authentication and authorization. Published as an npm package, it provides guards, decorators, and services for JWT validation, role-based access control, and resource permission enforcement via standard Keycloak OIDC endpoints.

## Core Stack

- NestJS (library, not application)
- TypeScript
- `@nestjs/axios` + `axios` for HTTP calls to Keycloak
- Node.js native `crypto` for JWT signature verification (no external JWT deps)

## Architecture

### Module Structure

```
src/
  keycloak-connect.module.ts     # Main dynamic module (register / registerAsync)
  keycloak-connect.providers.ts  # Provider factories (ResolvedTenantConfig)
  internal.util.ts               # Request extraction, tenant config resolution
  constants.ts                   # Injection tokens, enums
  util.ts                        # JWT payload parsing
  index.ts                       # Public API exports

  proxy/                         # HTTP proxy layer
    proxy.module.ts
    proxy.service.ts             # executeRequest, executeDynamicRequest, URL building
    proxy-config.service.ts      # Service config registry
    interfaces/
    types/

  token/
    keycloak-token.ts            # Native JWT Token class (hasRole, isExpired, etc.)

  services/
    keycloak-http.service.ts     # Typed Keycloak API (fetchJwks, introspect, checkPermission)
    jwks-cache.service.ts        # JWKS caching with key rotation support
    token-validation.service.ts  # Online (introspect) + offline (JWKS) validation
    keycloak-multitenant.service.ts  # Multi-tenant config resolution and caching

  guards/
    auth.guard.ts                # JWT validation (online/offline/none)
    role.guard.ts                # Role-based access (realm:role, client:role, role)
    resource.guard.ts            # Resource/scope enforcement via UMA

  decorators/                    # @Public, @Roles, @Resource, @Scopes, etc.
  interface/                     # Config, tenant, JWKS, enforcer options types
```

### Key Design Decisions

- **No `keycloak-connect` dependency** — all Keycloak interaction is via direct HTTP to standard OIDC endpoints
- **`ResolvedTenantConfig`** replaces Keycloak instances — plain data object `{ authServerUrl, realm, clientId, secret, realmUrl }`
- **Proxy module** handles HTTP mechanics (URL building, header merging, timeouts); `KeycloakHttpService` provides typed Keycloak API on top
- **`KeycloakToken.hasRole()`** matches keycloak-connect's three-form logic: `"role"`, `"realm:role"`, `"client:role"`
- **Node native crypto** for JWK-to-public-key conversion and signature verification (no `jwk-to-pem`)

## Workflow

### Verification Before Done

- Run `npm run build` (TypeScript compilation) after code changes
- Run `npm run lint` (ESLint) before finishing
- Ensure no `keycloak-connect` imports remain in `src/`

### Git Rules

- Do not run `git commit` or `git push` automatically
- Read-only git commands are always fine: `git status`, `git diff`, `git log`
- Developer reviews diffs and performs commit/push manually

## Code Conventions

- 3-space indentation (enforced by ESLint)
- Single quotes (enforced by ESLint)
- Max line length: 120 characters
- Pre-commit hook runs `lint-staged` (prettier + eslint on staged `.ts` files)
- `any` types are warned but acceptable for request objects and dynamic interfaces

## AI Agent Skills

Project-level skills for Claude Code and Codex live under `.claude/skills/`. Claude Code picks them up automatically. To register them into Codex, run the setup script once:

```bash
# macOS / Linux
bash scripts/setup-codex-skills.sh

# Windows (PowerShell)
pwsh -File scripts/setup-codex-skills.ps1
```

When a skill is obviously relevant, follow it instead of inventing a new workflow.

| Skill | Purpose |
|---|---|
| `review` | Review changes against conventions before handoff |
| `handoff` | Generate a handoff document for session continuity |
| `sort-imports` | Sort TypeScript imports by line length |
| `typescript-review` | Strict code review for TS/NestJS changes |
| `security-audit` | Auth-library-focused security vulnerability audit |

## Key Commands

```bash
npm run build          # Compile TypeScript
npm run lint           # Run ESLint
npm run format         # Run Prettier
npm run clean          # Remove dist/
npm run release        # Release via release-it
```

## Key Files

- Module entry: `src/keycloak-connect.module.ts`
- Public API: `src/index.ts`
- Package config: `package.json`
- TypeScript config: `tsconfig.json`
- ESLint config: `eslint.config.mjs`
- Husky pre-commit: `.husky/pre-commit`
- CI workflow: `.github/workflows/build.yml`
