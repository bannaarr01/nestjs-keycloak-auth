---
name: typescript-review
description: Run a strict TypeScript code review on current changes with focus on correctness, architecture, maintainability, and type safety.
---

Review target: $ARGUMENTS

If no target is provided, review the current working diff (`git diff`).

## Goal

Deliver a high-signal code review for TypeScript/NestJS library code that catches real bugs and architectural violations before merge.

Priority order:
1. Bugs and behavioural regressions
2. Security and auth gaps
3. Unsafe type usage and contract leaks
4. Architecture and layering violations
5. Public API compatibility

## Review Procedure

### Step 1 — Collect Scope

- Read `git status` and `git diff` (staged + unstaged).
- If files are provided as arguments, restrict scope to those files.
- Identify touched areas and their upstream/downstream dependencies.
- Note whether the change touches auth logic, token validation, public API surface, or proxy layer.

### Step 2 — Functional Correctness

| Check                                    | Risk if missed                          |
|------------------------------------------|-----------------------------------------|
| Null/undefined paths, unhandled branches | Runtime crash, silent data corruption   |
| Async/await misuse, floating promises    | Silent failures, race conditions        |
| Incorrect error types (HttpException)    | Wrong status codes to consumers         |
| Error swallowing (empty catch blocks)    | Invisible production failures           |
| Off-by-one, boundary conditions          | Subtle logic bugs                       |
| JWT parsing edge cases                   | Auth bypass or crash on malformed tokens|

### Step 3 — TypeScript Quality

| Check                                    | Why it matters                          |
|------------------------------------------|-----------------------------------------|
| `any` usage without clear justification  | Type safety erosion                     |
| Missing return type on exported function | Public API contract unclear             |
| Floating promise (no await/return/catch) | Silent failures                         |
| Unsafe casts, non-null assertions (`!`)  | Runtime crashes                         |
| Unused imports or variables              | Code hygiene (enforced by lint)         |
| Implicit type widening                   | Unexpected behaviour                    |

### Step 4 — Library Architecture

| Check                                    | Violation signal                        |
|------------------------------------------|-----------------------------------------|
| Guard/service/decorator boundaries       | Logic in wrong layer                    |
| Proxy layer concerns leaking up          | HTTP details exposed to guards          |
| Missing DI registration                  | Runtime NestJS injection errors         |
| Breaking public API changes              | Downstream consumers break              |
| Hardcoded config values                  | Should come from KeycloakConnectConfig  |
| Direct HTTP calls bypassing ProxyService | Inconsistent error handling             |

### Step 5 — Output Format

Report findings grouped by severity:

```markdown
### [High] Finding title
**File:** src/module/file.ts:42
**Issue:** Description of the problem.
**Impact:** What happens if this ships.
**Fix:** Concrete code change or approach.
```

Severity definitions:
- **High**: correctness bug, security hole, data loss, auth bypass, runtime crash
- **Medium**: likely bug, significant maintainability risk, public API concern
- **Low**: style improvement, minor readability issue, non-blocking suggestion

If no findings: state `No critical findings.` and list:
- Residual risks or areas not fully covered
- Suggestions for follow-up improvements (clearly marked as non-blocking)
