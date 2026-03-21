/**
 * Local replacement for keycloak-connect's EnforcerOptions.
 */
export interface KeycloakEnforcerOptions {
  response_mode?: 'permissions' | 'token';
  resource_server_id?: string;
  claims?: (request: unknown) => Record<string, unknown>;
}
