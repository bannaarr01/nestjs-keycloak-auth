export interface KeycloakRequestLike {
  headers: Record<string, string | string[] | undefined>;
  user?: Record<string, unknown>;
  accessToken?: string;
  scopes?: string[];
  permissions?: unknown[];
  [key: string]: unknown;
}
