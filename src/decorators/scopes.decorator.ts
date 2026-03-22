import { extractRequest } from '../internal.util';
import { ConditionalScopeFn } from '../types/conditional-scope.type';
import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';

export { ConditionalScopeFn };

export const META_SCOPES = 'scopes';

export const META_CONDITIONAL_SCOPES = 'conditional-scopes';

/**
 * Keycloak authorization scopes.
 * @param scopes - scopes that are associated with the resource
 */
export const Scopes = (...scopes: string[]) => SetMetadata(META_SCOPES, scopes);

/**
 * Keycloak authorization conditional scopes.
 * @param resolver
 */
export const ConditionalScopes = (resolver: ConditionalScopeFn) =>
   SetMetadata(META_CONDITIONAL_SCOPES, resolver);

/**
 * Retrieves the resolved scopes.
 * @since 1.5.0
 */
export const ResolvedScopes = createParamDecorator(
   (data: unknown, ctx: ExecutionContext) => {
      const [req] = extractRequest(ctx);
      return req.scopes;
   },
);
