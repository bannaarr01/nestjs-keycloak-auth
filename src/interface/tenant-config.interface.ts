/**
 * Resolved tenant configuration — plain data replacing keycloak-connect's Keycloak instance.
 */
export interface ResolvedTenantConfig {
  authServerUrl: string;
  realm: string;
  clientId: string;
  secret: string;
  realmUrl: string;
  realmAdminUrl: string;
  isPublic: boolean;
  bearerOnly: boolean;
}
