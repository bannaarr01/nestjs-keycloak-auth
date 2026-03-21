/**
 * Local replacement for keycloak-connect's EnforcerOptions.
 */
export interface KeycloakEnforcerOptions {
  response_mode?: 'permissions' | 'token';
  claims?: (request: any) => Record<string, string[]>;
}
