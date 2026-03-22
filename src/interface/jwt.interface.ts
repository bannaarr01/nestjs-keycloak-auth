export interface JwtHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JwtPermission {
  rsid?: string;
  rsname?: string;
  scopes?: string[];
}

export interface JwtContent {
  exp: number;
  iat?: number;
  typ?: string;
  iss?: string;
  aud?: string | string[];
  azp?: string;
  sub?: string;
  preferred_username?: string;
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
  authorization?: { permissions: JwtPermission[] };
  // OAuth2 scope claim (space-delimited string, e.g. "openid profile email")
  scope?: string;
  // OIDC session ID
  sid?: string;
  // OIDC back-channel logout events claim
  events?: Record<string, unknown>;
  // Admin callback fields
  action?: string;
  adapterSessionIds?: string[];
  notBefore?: number;
  [key: string]: unknown;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  preferred_username?: string;
  [key: string]: unknown;
}
