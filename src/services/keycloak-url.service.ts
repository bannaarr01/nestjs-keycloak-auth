import { Inject, Injectable } from '@nestjs/common';
import { KEYCLOAK_CONNECT_OPTIONS } from '../constants';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';

/**
 * Service for generating Keycloak endpoint URLs.
 * Matches keycloak-connect's loginUrl, logoutUrl, and accountUrl methods.
 */
@Injectable()
export class KeycloakUrlService {
  private readonly realmUrl: string;

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
  ) {
    const authServerUrl = (
      this.keycloakOpts.authServerUrl ||
      this.keycloakOpts['auth-server-url'] ||
      this.keycloakOpts.serverUrl ||
      this.keycloakOpts['server-url'] ||
      ''
    ).replace(/\/+$/, '');
    const realm = this.keycloakOpts.realm || '';
    this.realmUrl = realm ? `${authServerUrl}/realms/${realm}` : authServerUrl;
  }

  /**
   * Build a Keycloak login URL for the authorization code flow.
   */
  loginUrl(state: string, redirectUri: string): string {
    const clientId =
      this.keycloakOpts.clientId ||
      this.keycloakOpts['client-id'] ||
      this.keycloakOpts.resource ||
      '';

    const scope = this.keycloakOpts.scope
      ? `openid ${this.keycloakOpts.scope}`
      : 'openid';

    let url =
      this.realmUrl +
      '/protocol/openid-connect/auth' +
      '?client_id=' +
      encodeURIComponent(clientId) +
      '&state=' +
      encodeURIComponent(state) +
      '&redirect_uri=' +
      encodeURIComponent(redirectUri) +
      '&scope=' +
      encodeURIComponent(scope) +
      '&response_type=code';

    const idpHint = this.keycloakOpts.idpHint;
    if (idpHint) {
      url += '&kc_idp_hint=' + encodeURIComponent(idpHint);
    }

    return url;
  }

  /**
   * Build a Keycloak logout URL.
   */
  logoutUrl(redirectUrl?: string, idTokenHint?: string): string {
    const url = new URL(this.realmUrl + '/protocol/openid-connect/logout');

    if (redirectUrl && idTokenHint) {
      url.searchParams.set('id_token_hint', idTokenHint);
      url.searchParams.set('post_logout_redirect_uri', redirectUrl);
    }

    return url.toString();
  }

  /**
   * Get the Keycloak account management URL.
   */
  accountUrl(): string {
    return this.realmUrl + '/account';
  }

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
