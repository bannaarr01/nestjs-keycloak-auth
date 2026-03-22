import { HeaderValue } from '../types/header-value.type';

export interface TenantResolverRequest {
  headers?: Record<string, HeaderValue>;
  hostname?: string;
}
