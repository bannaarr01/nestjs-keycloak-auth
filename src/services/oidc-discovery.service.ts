import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';

/**
 * Discovered OIDC endpoint URLs from .well-known/openid-configuration.
 */
export interface OidcEndpoints {
  jwks_uri: string;
  token_endpoint: string;
  introspection_endpoint: string;
  userinfo_endpoint: string;
}

interface CachedDiscovery {
  endpoints: OidcEndpoints;
  fetchedAt: number;
}

/**
 * Fetches and caches OIDC discovery metadata per realm.
 * Endpoints are resolved from {realmUrl}/.well-known/openid-configuration
 * instead of being hardcoded.
 */
@Injectable()
export class OidcDiscoveryService {
  private readonly logger = new Logger(OidcDiscoveryService.name);
  private readonly cache = new Map<string, CachedDiscovery>();
  private readonly cacheTtlMs = 300_000; // 5 minutes

  constructor(private readonly httpService: HttpService) {}

  /**
   * Get the discovered OIDC endpoints for a realm URL.
   * Results are cached for 5 minutes per realm.
   */
  async getEndpoints(realmUrl: string): Promise<OidcEndpoints> {
    const cached = this.cache.get(realmUrl);
    if (cached && Date.now() - cached.fetchedAt < this.cacheTtlMs) {
      return cached.endpoints;
    }

    const discoveryUrl = `${realmUrl}/.well-known/openid-configuration`;

    this.logger.verbose(`Fetching OIDC discovery from ${discoveryUrl}`);

    const { data } = await firstValueFrom(
      this.httpService.request<Record<string, unknown>>({
        url: discoveryUrl,
        method: 'GET',
        headers: {
          Accept: 'application/json',
          'X-Client': 'nestjs-keycloak-auth',
        },
        timeout: 10000,
      }),
    );

    const endpoints: OidcEndpoints = {
      jwks_uri:
        (data.jwks_uri as string) ||
        `${realmUrl}/protocol/openid-connect/certs`,
      token_endpoint:
        (data.token_endpoint as string) ||
        `${realmUrl}/protocol/openid-connect/token`,
      introspection_endpoint:
        (data.introspection_endpoint as string) ||
        `${realmUrl}/protocol/openid-connect/token/introspect`,
      userinfo_endpoint:
        (data.userinfo_endpoint as string) ||
        `${realmUrl}/protocol/openid-connect/userinfo`,
    };

    this.cache.set(realmUrl, { endpoints, fetchedAt: Date.now() });
    return endpoints;
  }

  /**
   * Clear all cached discovery metadata.
   */
  clearCache(): void {
    this.cache.clear();
  }
}
