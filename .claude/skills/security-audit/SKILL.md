---
name: security-audit
description: Audit changed code for security vulnerabilities in the nestjs-keycloak-auth library and propose practical fixes, including patch-ready remediations when requested.
---

Audit target: $ARGUMENTS

If no target is provided, audit the current diff (`git diff`).

## Goal

Identify exploitable weaknesses in authentication/authorization library code and provide actionable remediations. This library handles JWT tokens, Keycloak OIDC, and access control — security is its core responsibility.

## Audit Procedure

### Step 1 — Scope and Attack Surface

Read changed files and map the security-critical areas:

| Area                     | What to look for                                      |
|--------------------------|-------------------------------------------------------|
| Token parsing            | Malformed JWT handling, base64 decoding edge cases    |
| Signature verification   | Algorithm confusion, missing kid validation, weak alg |
| Token validation         | Bypass paths, timing attacks, expiry check gaps       |
| Role/permission checking | Logic flaws in hasRole, privilege escalation paths    |
| HTTP calls to Keycloak   | SSRF via realmUrl/authServerUrl, credential leakage in logs/errors |
| Multi-tenant resolution  | Tenant isolation, realm spoofing, cache poisoning     |
| Guard bypass             | Public decorator misuse, missing guard on code paths  |
| Config handling          | Secret exposure, unsafe defaults, config injection    |

### Step 2 — Threat Analysis

Check against these categories relevant to an auth library:

| Category                       | Check                                                     |
|--------------------------------|-----------------------------------------------------------|
| Auth bypass                    | Can a request skip token validation entirely?             |
| Token forgery                  | Can an attacker craft a token that passes validation?     |
| Algorithm confusion            | Does offline validation enforce expected alg from JWKS?   |
| Privilege escalation           | Can hasRole() be tricked with crafted token payloads?     |
| Tenant isolation               | Can a token from realm A pass validation for realm B?     |
| Credential leakage             | Are client secrets logged, included in errors, or exposed?|
| SSRF via proxy                 | Can user-controlled input reach proxy baseUrl/endpoint?   |
| Cache poisoning                | Can JWKS cache be poisoned with attacker-controlled keys? |
| Timing attacks                 | Is token comparison timing-safe?                          |
| Denial of service              | Can malformed tokens cause crashes or resource exhaustion? |

### Step 3 — Implementation-Specific Checks

- **KeycloakToken**: Does it handle tokens with missing claims gracefully (no crash)?
- **JwksCacheService**: Is rate limiting effective? Can an attacker force excessive JWKS fetches?
- **TokenValidationService**: Does offline validation check issuer, expiry, AND signature (not just one)?
- **KeycloakHttpService**: Are Keycloak responses validated before use? Can error responses leak info?
- **Guards**: Is the `@Public()` decorator checked correctly? Are there TOCTOU issues between guards?
- **Multi-tenant**: Can the realm resolver be manipulated to resolve to an attacker-controlled server?
- **BackchannelLogoutService**: Can revocation entries expire correctly? Is TTL cleanup race-free?
- **Error hierarchy**: Do error messages leak sensitive details (secrets, full tokens, internal paths)?

### Step 4 — Remediation Design

For each finding:

1. **Minimal-risk fix** — smallest change to close the vulnerability
2. **Hardened option** — defence-in-depth improvement (if applicable)
3. **Verification** — how to confirm the fix works

When asked to implement fixes:
- Apply secure-by-default changes
- Keep the public API compatible unless explicitly approved otherwise
- Prefer failing closed (deny access) over failing open

### Step 5 — Output Format

```markdown
### [Severity] Finding title

**File:** path/to/file.ts:line
**Category:** Auth bypass / Token forgery / Credential leakage / etc.
**Exploit scenario:** One sentence describing how this could be exploited.

**Recommended fix:**
[Code diff or description]

**Verification:**
- Automated: [test assertion or build check]
- Manual: [steps to verify]
```

Severity levels: `Critical` > `High` > `Medium` > `Low`

If no findings: respond with `No critical vulnerabilities found in reviewed scope.` and list residual risk notes and areas not covered.
