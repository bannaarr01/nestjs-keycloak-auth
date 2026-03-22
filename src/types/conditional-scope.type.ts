import { KeycloakToken } from '../token/keycloak-token';

export type ConditionalScopeFn = (
  request: unknown,
  token: KeycloakToken,
) => string[];
