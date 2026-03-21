import { ProxyService } from '../proxy/proxy.service';
import { Injectable, OnModuleInit } from '@nestjs/common';
import { JwksResponse } from '../interface/jwks.interface';
import { ProxyConfigService } from '../proxy/proxy-config.service';
import {
  KeycloakGrantResponse,
  KeycloakPermission,
  KeycloakUserInfoResponse,
  PermissionCheckOptions,
} from '../interface/keycloak-grant.interface';

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
          'X-Client': 'keycloak-nodejs-connect',
        },
        timeoutMs: 10000,
        endpoints: {
          jwks: { targetEndpoint: 'protocol/openid-connect/certs' },
          introspect: {
            targetEndpoint: 'protocol/openid-connect/token/introspect',
          },
          token: { targetEndpoint: 'protocol/openid-connect/token' },
          userinfo: { targetEndpoint: 'protocol/openid-connect/userinfo' },
        },
      });
    }
  }

  /**
   * Build authorization headers for token endpoint requests.
   * Public clients send only client_id in the body; confidential clients
   * use HTTP Basic auth (matching keycloak-connect's postOptions).
   */
  private buildAuthHeaders(
    clientId: string,
    secret: string,
    isPublic: boolean,
  ): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Client': 'keycloak-nodejs-connect',
    };
    if (!isPublic) {
      headers.Authorization = `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`;
    }
    return headers;
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
        headers: {
          'Content-Type': 'application/json',
          'X-Client': 'keycloak-nodejs-connect',
        },
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
   * Obtain a token using the client credentials grant (service account).
   */
  async obtainClientCredentialsGrant(
    realmUrl: string,
    clientId: string,
    secret: string,
    scope?: string,
    isPublic: boolean = false,
  ): Promise<KeycloakGrantResponse> {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: scope || 'openid',
      client_id: clientId,
    });

    return this.proxyService.executeRequest<KeycloakGrantResponse>(
      KEYCLOAK_SERVICE,
      'token',
      'POST',
      {
        data: params.toString(),
        headers: this.buildAuthHeaders(clientId, secret, isPublic),
      },
      realmUrl,
    );
  }

  /**
   * Obtain a token using the resource owner password credentials grant (direct grant).
   */
  async obtainDirectGrant(
    realmUrl: string,
    clientId: string,
    secret: string,
    username: string,
    password: string,
    scope?: string,
    isPublic: boolean = false,
  ): Promise<KeycloakGrantResponse> {
    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: clientId,
      username,
      password,
      scope: scope || 'openid',
    });

    return this.proxyService.executeRequest<KeycloakGrantResponse>(
      KEYCLOAK_SERVICE,
      'token',
      'POST',
      {
        data: params.toString(),
        headers: this.buildAuthHeaders(clientId, secret, isPublic),
      },
      realmUrl,
    );
  }

  /**
   * Refresh an access token using a refresh_token.
   */
  async refreshToken(
    realmUrl: string,
    clientId: string,
    secret: string,
    refreshToken: string,
    isPublic: boolean = false,
  ): Promise<KeycloakGrantResponse> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    });

    return this.proxyService.executeRequest<KeycloakGrantResponse>(
      KEYCLOAK_SERVICE,
      'token',
      'POST',
      {
        data: params.toString(),
        headers: this.buildAuthHeaders(clientId, secret, isPublic),
      },
      realmUrl,
    );
  }

  /**
   * Fetch user info from the Keycloak userinfo endpoint.
   */
  async getUserInfo(
    realmUrl: string,
    accessToken: string,
  ): Promise<KeycloakUserInfoResponse> {
    return this.proxyService.executeRequest<KeycloakUserInfoResponse>(
      KEYCLOAK_SERVICE,
      'userinfo',
      'GET',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
          'X-Client': 'keycloak-nodejs-connect',
        },
      },
      realmUrl,
    );
  }

  /**
   * Check permissions using the Keycloak token endpoint (UMA grant).
   * Supports response_mode 'decision' (returns boolean), 'permissions'
   * (returns permission list), and 'token' (returns grant response).
   */
  async checkPermission(
    realmUrl: string,
    clientId: string,
    secret: string,
    accessToken: string,
    permissions: string[],
    options?: PermissionCheckOptions,
  ): Promise<boolean | KeycloakPermission[] | KeycloakGrantResponse> {
    const responseMode = options?.response_mode || 'decision';
    const audience = options?.audience || clientId;
    const isPublic = options?.isPublic ?? false;

    const params = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
      audience,
    });

    // Only set response_mode for 'decision' and 'permissions';
    // 'token' mode omits it to get a grant response (matching original behavior)
    if (responseMode === 'decision' || responseMode === 'permissions') {
      params.set('response_mode', responseMode);
    }

    for (const permission of permissions) {
      params.append('permission', permission);
    }

    if (options?.claims) {
      params.set(
        'claim_token',
        Buffer.from(JSON.stringify(options.claims)).toString('base64'),
      );
      params.set('claim_token_format', 'urn:ietf:params:oauth:token-type:jwt');
    }

    if (options?.subject_token) {
      params.set('subject_token', options.subject_token);
    } else if (!isPublic) {
      // Confidential clients send the user bearer as subject_token.
      params.set('subject_token', accessToken);
    }

    try {
      const headers = isPublic
        ? {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Client': 'keycloak-nodejs-connect',
          }
        : this.buildAuthHeaders(clientId, secret, false);

      const result = await this.proxyService.executeRequest<
        Record<string, unknown>
      >(
        KEYCLOAK_SERVICE,
        'token',
        'POST',
        {
          data: params.toString(),
          headers,
        },
        realmUrl,
      );

      if (responseMode === 'decision') {
        return result?.result === true;
      }

      // 'permissions' and 'token' modes return the raw response
      if (responseMode === 'permissions') {
        return result as unknown as KeycloakPermission[];
      }
      return result as unknown as KeycloakGrantResponse;
    } catch {
      if (responseMode === 'decision') {
        return false;
      }
      throw new Error('Permission check failed');
    }
  }
}
