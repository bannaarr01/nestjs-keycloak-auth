import { SetMetadata } from '@nestjs/common';

export const META_TOKEN_SCOPES = 'token-scopes';

/**
 * Decorator to require specific OAuth2 scopes from the JWT `scope` claim.
 *
 * Unlike `@Scopes()` which checks UMA resource permissions, this decorator
 * validates the space-delimited `scope` string in the access token itself
 * (e.g. `"openid profile email"`).
 *
 * Enforced by `AuthGuard` — returns 403 Forbidden when required scopes
 * are missing (the user is authenticated but lacks the granted scope).
 *
 * @example
 * ```ts
 * @Get('profile')
 * @TokenScopes('openid', 'profile')
 * getProfile() { ... }
 * ```
 */
export const TokenScopes = (...scopes: string[]) =>
   SetMetadata(META_TOKEN_SCOPES, scopes);
