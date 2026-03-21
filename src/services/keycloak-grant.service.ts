import { KEYCLOAK_CONNECT_OPTIONS } from '../constants';
import { KeycloakGrant } from '../token/keycloak-grant';
import { KeycloakToken } from '../token/keycloak-token';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { KeycloakHttpService } from './keycloak-http.service';
import { TokenValidationService } from './token-validation.service';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';

/**
 * Service for creating, validating, and refreshing Keycloak grants.
 * Replaces keycloak-connect's GrantManager grant lifecycle methods.
 */
@Injectable()
export class KeycloakGrantService {
  private readonly logger = new Logger(KeycloakGrantService.name);
  private readonly bearerOnly: boolean;
  private readonly clientId: string;

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
    private readonly keycloakHttp: KeycloakHttpService,
    private readonly tokenValidation: TokenValidationService,
  ) {
    this.bearerOnly = !!(
      this.keycloakOpts.bearerOnly ??
      this.keycloakOpts['bearer-only'] ??
      false
    );
    this.clientId =
      this.keycloakOpts.clientId ||
      this.keycloakOpts['client-id'] ||
      this.keycloakOpts.resource ||
      '';
  }

  /**
   * Create a Grant object from raw JSON data (string or object).
   * Parses tokens, ensures freshness if refreshable, and validates.
   * Matches keycloak-connect GrantManager.createGrant().
   */
  async createGrant(
    rawData: string | Record<string, unknown>,
    realmUrl: string,
    clientId?: string,
    secret?: string,
  ): Promise<KeycloakGrant> {
    const grantData = (
      typeof rawData === 'string' ? JSON.parse(rawData) : rawData
    ) as Record<string, unknown>;
    const cId = clientId || this.clientId;

    const grant = new KeycloakGrant({
      access_token: grantData.access_token
        ? new KeycloakToken(grantData.access_token as string, cId)
        : undefined,
      refresh_token: grantData.refresh_token
        ? new KeycloakToken(grantData.refresh_token as string)
        : undefined,
      id_token: grantData.id_token
        ? new KeycloakToken(grantData.id_token as string)
        : undefined,
      expires_in: grantData.expires_in as number | undefined,
      token_type: grantData.token_type as string | undefined,
      __raw: typeof rawData === 'string' ? rawData : JSON.stringify(rawData),
    });

    if (this.isGrantRefreshable(grant) && secret) {
      await this.ensureFreshness(grant, realmUrl, cId, secret);
    }

    await this.validateGrant(grant, realmUrl, cId);

    return grant;
  }

  /**
   * Check if a grant can be refreshed.
   * Matches keycloak-connect GrantManager.isGrantRefreshable().
   */
  isGrantRefreshable(grant: KeycloakGrant): boolean {
    return !this.bearerOnly && !!grant.refresh_token;
  }

  /**
   * Ensure that a grant is fresh, refreshing if required and possible.
   * Matches keycloak-connect GrantManager.ensureFreshness().
   */
  async ensureFreshness(
    grant: KeycloakGrant,
    realmUrl: string,
    clientId: string,
    secret: string,
  ): Promise<KeycloakGrant> {
    if (!grant.isExpired()) {
      return grant;
    }

    if (!grant.refresh_token) {
      throw new Error('Unable to refresh without a refresh token');
    }

    if (grant.refresh_token.isExpired()) {
      throw new Error('Unable to refresh with expired refresh token');
    }

    const isPublic = !!(
      this.keycloakOpts['public-client'] ??
      this.keycloakOpts.public ??
      false
    );

    const response = await this.keycloakHttp.refreshToken(
      realmUrl,
      clientId,
      secret,
      grant.refresh_token.token,
      isPublic,
    );

    const newGrant = new KeycloakGrant({
      access_token: response.access_token
        ? new KeycloakToken(response.access_token, clientId)
        : undefined,
      refresh_token: response.refresh_token
        ? new KeycloakToken(response.refresh_token)
        : undefined,
      id_token: response.id_token
        ? new KeycloakToken(response.id_token)
        : undefined,
      expires_in: response.expires_in,
      token_type: response.token_type,
      __raw: JSON.stringify(response),
    });

    grant.update(newGrant);
    return grant;
  }

  /**
   * Validate all tokens in a grant.
   * Matches keycloak-connect GrantManager.validateGrant().
   */
  async validateGrant(
    grant: KeycloakGrant,
    realmUrl: string,
    clientId?: string,
  ): Promise<KeycloakGrant> {
    const cId = clientId || this.clientId;

    // Validate access token as Bearer type
    if (grant.access_token) {
      const isValid = await this.tokenValidation.validateOffline(
        grant.access_token.token,
        realmUrl,
        cId,
        'Bearer',
      );
      if (!isValid) {
        throw new Error(
          'Grant validation failed. Reason: invalid access_token',
        );
      }
    }

    // Validate ID token if not bearer-only
    if (!this.bearerOnly && grant.id_token) {
      const isValid = await this.tokenValidation.validateOffline(
        grant.id_token.token,
        realmUrl,
        cId,
        'ID',
      );
      if (!isValid) {
        throw new Error('Grant validation failed. Reason: invalid id_token');
      }
    }

    return grant;
  }
}
