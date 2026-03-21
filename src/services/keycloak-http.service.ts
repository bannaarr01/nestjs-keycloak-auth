import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { JwksResponse } from '../interface/jwks.interface';
import { OidcDiscoveryService } from './oidc-discovery.service';
import {
  KeycloakGrantResponse,
  KeycloakPermission,
  KeycloakUserInfoResponse,
  PermissionCheckOptions,
} from '../interface/keycloak-grant.interface';

const X_CLIENT = 'nestjs-keycloak-auth';

@Injectable()
export class KeycloakHttpService {
  constructor(
    private readonly httpService: HttpService,
    private readonly oidcDiscovery: OidcDiscoveryService,
  ) {}

  /**
   * Build authorization headers for token endpoint requests.
   * Public clients send only client_id in the body; confidential clients
   * use HTTP Basic auth.
   */
  private buildAuthHeaders(
    clientId: string,
    secret: string,
    isPublic: boolean,
  ): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Client': X_CLIENT,
    };
    if (!isPublic) {
      headers.Authorization = `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`;
    }
    return headers;
  }

  /**
   * Fetch the JWKS (JSON Web Key Set) from the discovered jwks_uri.
   */
  async fetchJwks(realmUrl: string): Promise<JwksResponse> {
    const endpoints = await this.oidcDiscovery.getEndpoints(realmUrl);
    const { data } = await firstValueFrom(
      this.httpService.request<JwksResponse>({
        url: endpoints.jwks_uri,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'X-Client': X_CLIENT,
        },
        timeout: 10000,
      }),
    );
    return data;
  }

  /**
   * Introspect a token using the discovered introspection_endpoint.
   * Returns the introspection response (with `active` boolean).
   */
  async introspectToken(
    realmUrl: string,
    clientId: string,
    secret: string,
    token: string,
  ): Promise<{ active: boolean; [key: string]: unknown }> {
    const endpoints = await this.oidcDiscovery.getEndpoints(realmUrl);
    const body = new URLSearchParams({
      client_id: clientId,
      client_secret: secret,
      token,
    }).toString();

    const { data } = await firstValueFrom(
      this.httpService.request<{ active: boolean; [key: string]: unknown }>({
        url: endpoints.introspection_endpoint,
        method: 'POST',
        data: body,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Client': X_CLIENT,
        },
        timeout: 10000,
      }),
    );
    return data;
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
    const endpoints = await this.oidcDiscovery.getEndpoints(realmUrl);
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: scope || 'openid',
      client_id: clientId,
    });

    const { data } = await firstValueFrom(
      this.httpService.request<KeycloakGrantResponse>({
        url: endpoints.token_endpoint,
        method: 'POST',
        data: params.toString(),
        headers: this.buildAuthHeaders(clientId, secret, isPublic),
        timeout: 10000,
      }),
    );
    return data;
  }

  /**
   * Fetch user info from the discovered userinfo_endpoint.
   */
  async getUserInfo(
    realmUrl: string,
    accessToken: string,
  ): Promise<KeycloakUserInfoResponse> {
    const endpoints = await this.oidcDiscovery.getEndpoints(realmUrl);
    const { data } = await firstValueFrom(
      this.httpService.request<KeycloakUserInfoResponse>({
        url: endpoints.userinfo_endpoint,
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/json',
          'X-Client': X_CLIENT,
        },
        timeout: 10000,
      }),
    );
    return data;
  }

  /**
   * Check permissions using the discovered token_endpoint (UMA grant).
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
    const endpoints = await this.oidcDiscovery.getEndpoints(realmUrl);
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
            'X-Client': X_CLIENT,
          }
        : this.buildAuthHeaders(clientId, secret, false);

      const { data: result } = await firstValueFrom(
        this.httpService.request<Record<string, unknown>>({
          url: endpoints.token_endpoint,
          method: 'POST',
          data: params.toString(),
          headers,
          timeout: 10000,
        }),
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
