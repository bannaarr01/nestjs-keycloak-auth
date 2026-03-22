# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a vulnerability

If you discover a security vulnerability in this package, please report it responsibly.

**Do not open a public GitHub issue.**

Instead, email **tbannaarr@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect an initial response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Scope

This package handles JWT token validation, Keycloak OIDC integration, and access control. Security issues in these areas are treated with the highest priority:

- Token validation bypass
- Authentication or authorization bypass
- Credential leakage (secrets in logs or error messages)
- Tenant isolation failures in multi-tenant mode
