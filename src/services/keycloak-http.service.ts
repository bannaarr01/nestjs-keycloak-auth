import { Injectable, OnModuleInit } from '@nestjs/common';
import { ProxyService } from '../proxy/proxy.service';
import { ProxyConfigService } from '../proxy/proxy-config.service';
import { JwksResponse } from '../interface/jwks.interface';

const KEYCLOAK_SERVICE = 'keycloak';

@Injectable()
export class KeycloakHttpService implements OnModuleInit {
  constructor(
    private readonly proxyService: ProxyService,
    private readonly proxyConfigService: ProxyConfigService,
  ) {}

  onModuleInit() {
    // Register a default keycloak service config.
    // The baseUrl will be overridden per-request for multi-tenant,
    // or set to the single-tenant realmUrl.
    if (!this.proxyConfigService.getServiceConfig(KEYCLOAK_SERVICE)) {
      this.proxyConfigService.setServiceConfig(KEYCLOAK_SERVICE, {
        baseUrl: 'http://localhost', // placeholder, overridden per-request
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeoutMs: 10000,
        endpoints: {
          jwks: { targetEndpoint: 'protocol/openid-connect/certs' },
          introspect: {
            targetEndpoint: 'protocol/openid-connect/token/introspect',
          },
          token: { targetEndpoint: 'protocol/openid-connect/token' },
        },
      });
    }
  }

  /**
   * Fetch the JWKS (JSON Web Key Set) from the Keycloak realm.
   */
  async fetchJwks(realmUrl: string): Promise<JwksResponse> {
    return this.proxyService.executeRequest<JwksResponse>(
      KEYCLOAK_SERVICE,
      'jwks',
      'GET',
      {
        headers: { 'Content-Type': 'application/json' },
      },
      realmUrl,
    );
  }

  /**
   * Introspect a token using the Keycloak token introspection endpoint.
   * Returns the introspection response (with `active` boolean).
   */
  async introspectToken(
    realmUrl: string,
    clientId: string,
    secret: string,
    token: string,
  ): Promise<{ active: boolean; [key: string]: unknown }> {
    const data = new URLSearchParams({
      client_id: clientId,
      client_secret: secret,
      token,
    }).toString();

    return this.proxyService.executeRequest(
      KEYCLOAK_SERVICE,
      'introspect',
      'POST',
      { data },
      realmUrl,
    );
  }

  /**
   * Check permissions using the Keycloak token endpoint (UMA grant).
   * Returns true if the token has the requested permissions.
   */
  async checkPermission(
    realmUrl: string,
    clientId: string,
    secret: string,
    accessToken: string,
    permissions: string[],
  ): Promise<boolean> {
    const params = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
      audience: clientId,
      response_mode: 'decision',
    });

    for (const permission of permissions) {
      params.append('permission', permission);
    }

    try {
      const result = await this.proxyService.executeRequest<{
        result: boolean;
      }>(
        KEYCLOAK_SERVICE,
        'token',
        'POST',
        {
          data: params.toString(),
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
        realmUrl,
      );
      return result?.result === true;
    } catch {
      return false;
    }
  }
}
