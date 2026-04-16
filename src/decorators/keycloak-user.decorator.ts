import { extractRequest } from '../internal.util';
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Retrieves the current authenticated user from the request.
 * @since 1.5.0
 */
export const AuthenticatedUser = createParamDecorator(
   (data: unknown, ctx: ExecutionContext) => {
      const [req] = extractRequest(ctx);
      return req.user;
   },
);

/**
 * @deprecated Use `AuthenticatedUser` instead.
 */
export const KeycloakUser = AuthenticatedUser;
