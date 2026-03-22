import { HeaderValue } from '../types/header-value.type';
import { KeycloakRequestLike } from 'nestjs-keycloak-auth';

export interface ProductRequest extends KeycloakRequestLike {
  headers: Record<string, HeaderValue>;
  permissions?: unknown[];
}
