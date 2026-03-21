export interface KeycloakGrantResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token?: string;
  id_token?: string;
  refresh_expires_in?: number;
  scope?: string;
  'not-before-policy'?: number;
  session_state?: string;
}

export interface KeycloakUserInfoResponse {
  sub: string;
  name?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  email_verified?: boolean;
  [key: string]: unknown;
}

export interface PermissionCheckOptions {
  claims?: Record<string, unknown>;
  response_mode?: 'decision' | 'permissions' | 'token';
  audience?: string;
  subject_token?: string;
}

export interface KeycloakPermission {
  rsid?: string;
  rsname?: string;
  scopes?: string[];
}
