import { extractRequest } from '../internal.util';
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Retrieves the current Keycloak logged-in user.
 * @since 1.5.0
 */
export const KeycloakUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const [req] = extractRequest(ctx);
    return req.user;
  },
);
