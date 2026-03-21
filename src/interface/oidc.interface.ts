/**
 * Discovered OIDC endpoint URLs from .well-known/openid-configuration.
 */
export interface OidcEndpoints {
  jwks_uri: string;
  token_endpoint: string;
  introspection_endpoint: string;
  userinfo_endpoint: string;
}

export interface CachedDiscovery {
  endpoints: OidcEndpoints;
  fetchedAt: number;
}
