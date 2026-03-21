import { KeycloakToken } from './keycloak-token';

/**
 * Represents a Keycloak grant containing an access token.
 */
export class KeycloakGrant {
  access_token: KeycloakToken | undefined;
  token_type: string | undefined;
  expires_in: number | undefined;
  __raw: string | undefined;

  constructor(grant: Partial<KeycloakGrant>) {
    this.update(grant);
  }

  /**
   * Update this grant in-place given data in another grant.
   */
  update(grant: Partial<KeycloakGrant>): void {
    this.access_token = grant.access_token;
    this.token_type = grant.token_type;
    this.expires_in = grant.expires_in;
    this.__raw = grant.__raw;
  }

  /**
   * Returns the raw String of the grant, if available.
   */
  toString(): string | undefined {
    return this.__raw;
  }

  /**
   * Determine if this grant is expired/out-of-date.
   * Determination is made based upon the expiration status of the access_token.
   */
  isExpired(): boolean {
    if (!this.access_token) {
      return true;
    }
    return this.access_token.isExpired();
  }
}
