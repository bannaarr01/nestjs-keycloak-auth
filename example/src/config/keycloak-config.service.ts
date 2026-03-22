import { Injectable } from '@nestjs/common';
import { HeaderValue } from '../types/header-value.type';
import { TenantResolverRequest } from '../interface/tenant-resolver-request.interface';
import {
   RoleMerge,
   TokenValidation,
   KeycloakAuthOptions,
   PolicyEnforcementMode,
   KeycloakAuthOptionsFactory,
} from 'nestjs-keycloak-auth';

@Injectable()
export class KeycloakConfigService implements KeycloakAuthOptionsFactory {
  createKeycloakAuthOptions(): KeycloakAuthOptions {
    const authServerUrl = process.env.KC_AUTH_SERVER_URL ?? 'http://localhost:8080';
    const defaultRealm = process.env.KC_REALM ?? 'nest-example';
    const defaultClientId = process.env.KC_CLIENT_ID ?? 'nest-api';
    const defaultSecret =
      process.env.KC_CLIENT_SECRET ?? 'HwKxokCTFh4KcGhCW3KYXyypygD0S7D5';

    const tenantClientIds: Record<string, string> = {
      [defaultRealm]: defaultClientId,
      'tenant-a': process.env.KC_TENANT_A_CLIENT_ID ?? defaultClientId,
      'tenant-b': process.env.KC_TENANT_B_CLIENT_ID ?? defaultClientId,
    };

    const tenantSecrets: Record<string, string> = {
      [defaultRealm]: defaultSecret,
      'tenant-a':
        process.env.KC_TENANT_A_CLIENT_SECRET ?? 'kJuDbNnpAy2DuMSkLsl5Xx9XZ7nP86FS',
      'tenant-b':
        process.env.KC_TENANT_B_CLIENT_SECRET ?? '4o4O7jt58LKCBcPb6kdTnzsRY0bLMcX0',
    };

    const tenantAuthServers: Record<string, string> = {
      [defaultRealm]: authServerUrl,
      'tenant-a': process.env.KC_TENANT_A_AUTH_SERVER_URL ?? authServerUrl,
      'tenant-b': process.env.KC_TENANT_B_AUTH_SERVER_URL ?? authServerUrl,
    };

    return {
      authServerUrl,
      realm: defaultRealm,
      clientId: defaultClientId,
      secret: defaultSecret,
      bearerOnly: true,
      verifyTokenAudience: true,
      minTimeBetweenJwksRequests: 1,
      policyEnforcement: this.resolvePolicyEnforcement(
        process.env.KC_POLICY_ENFORCEMENT,
      ),
      tokenValidation: this.resolveTokenValidation(
        process.env.KC_TOKEN_VALIDATION,
      ),
      roleMerge: RoleMerge.ALL,
      multiTenant: {
        resolveAlways: true,
        realmResolver: (request: unknown) =>
          this.resolveRealm(request as TenantResolverRequest, defaultRealm),
        realmClientIdResolver: (realm: string) =>
          tenantClientIds[realm] ?? defaultClientId,
        realmSecretResolver: (realm: string) => tenantSecrets[realm] ?? defaultSecret,
        realmAuthServerUrlResolver: (realm: string) =>
          tenantAuthServers[realm] ?? authServerUrl,
      },
    };
  }

  private resolveTokenValidation(value: string | undefined): TokenValidation {
    const normalized = value?.trim().toLowerCase();
    if (normalized === TokenValidation.ONLINE) {
      return TokenValidation.ONLINE;
    }
    if (normalized === TokenValidation.NONE) {
      return TokenValidation.NONE;
    }
    return TokenValidation.OFFLINE;
  }

  private resolvePolicyEnforcement(
    value: string | undefined,
  ): PolicyEnforcementMode {
    const normalized = value?.trim().toLowerCase();
    if (normalized === PolicyEnforcementMode.ENFORCING) {
      return PolicyEnforcementMode.ENFORCING;
    }
    return PolicyEnforcementMode.PERMISSIVE;
  }

  private resolveRealm(
    request: TenantResolverRequest,
    fallbackRealm: string,
  ): string {
    const headerRealm = this.getHeaderValue(request.headers, 'x-tenant-realm');
    if (headerRealm) {
      return headerRealm;
    }

    const host = this.getHeaderValue(request.headers, 'x-forwarded-host')
      ?? request.hostname;
    if (host) {
      const normalizedHost = host.split(':')[0];
      const firstSegment = normalizedHost.split('.')[0];
      if (
        firstSegment &&
        !['localhost', '127', '127.0.0.1', 'api'].includes(firstSegment)
      ) {
        return firstSegment;
      }
    }

    return fallbackRealm;
  }

  private getHeaderValue(
    headers: Record<string, HeaderValue> | undefined,
    key: string,
  ): string | undefined {
    const headerValue = headers?.[key];
    if (typeof headerValue === 'string') {
      const normalized = headerValue.trim();
      return normalized.length > 0 ? normalized : undefined;
    }
    if (Array.isArray(headerValue) && headerValue.length > 0) {
      const first = headerValue[0]?.trim();
      return first && first.length > 0 ? first : undefined;
    }
    return undefined;
  }
}
