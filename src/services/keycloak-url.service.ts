import { Inject, Injectable } from '@nestjs/common';
import { KEYCLOAK_CONNECT_OPTIONS } from '../constants';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';

/**
 * Service for generating Keycloak endpoint URLs.
 */
@Injectable()
export class KeycloakUrlService {
  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
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
