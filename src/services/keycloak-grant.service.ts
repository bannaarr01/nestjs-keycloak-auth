import { KEYCLOAK_AUTH_OPTIONS } from '../constants';
import { KeycloakGrant } from '../token/keycloak-grant';
import { KeycloakToken } from '../token/keycloak-token';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { TokenValidationService } from './token-validation.service';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';

/**
 * Service for creating and validating Keycloak grants.
 * Bearer-only: no refresh token or ID token handling.
 */
@Injectable()
export class KeycloakGrantService {
   private readonly logger = new Logger(KeycloakGrantService.name);
   private readonly clientId: string;

   constructor(
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private readonly keycloakOpts: KeycloakAuthConfig,
    private readonly tokenValidation: TokenValidationService,
   ) {
      this.clientId =
      this.keycloakOpts.clientId ||
      this.keycloakOpts['client-id'] ||
      this.keycloakOpts.resource ||
      '';
   }

   /**
   * Create a Grant object from raw JSON data (string or object).
   * Parses the access token and validates.
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
         expires_in: grantData.expires_in as number | undefined,
         token_type: grantData.token_type as string | undefined,
         __raw: typeof rawData === 'string' ? rawData : JSON.stringify(rawData),
      });

      await this.validateGrant(grant, realmUrl, cId);

      return grant;
   }

   /**
   * Validate the access token in a grant.
   */
   async validateGrant(
      grant: KeycloakGrant,
      realmUrl: string,
      clientId?: string,
   ): Promise<KeycloakGrant> {
      const cId = clientId || this.clientId;

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

      return grant;
   }
}
