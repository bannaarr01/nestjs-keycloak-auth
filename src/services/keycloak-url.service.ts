import { Inject, Injectable } from '@nestjs/common';
import { KEYCLOAK_AUTH_OPTIONS } from '../constants';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';

/**
 * Service for generating Keycloak endpoint URLs.
 */
@Injectable()
export class KeycloakUrlService {
   constructor(
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private readonly keycloakOpts: KeycloakAuthConfig,
   ) {}

   /**
   * Get the realm admin API base URL.
   */
   realmAdminUrl(): string {
      const authServerUrl = (
         this.keycloakOpts.authServerUrl ||
      this.keycloakOpts['auth-server-url'] ||
      this.keycloakOpts.serverUrl ||
      this.keycloakOpts['server-url'] ||
      ''
      ).replace(/\/+$/, '');
      const realm = this.keycloakOpts.realm || '';
      return `${authServerUrl}/admin/realms/${realm}`;
   }
}
