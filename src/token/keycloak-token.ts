import { JwtContent, JwtHeader } from '../interface/jwt.interface';

export { JwtContent, JwtHeader };
export type { JwtPermission } from '../interface/jwt.interface';

/**
 * Native KeycloakToken class that replaces keycloak-connect's Token.
 * Parses a JWT and provides role/permission checking methods.
 */
export class KeycloakToken {
  readonly header: JwtHeader;
  readonly content: JwtContent;
  readonly signature: Buffer;
  readonly signed: string;

  constructor(
    private readonly _token: string,
    private readonly clientId?: string,
  ) {
    if (_token) {
      try {
        const parts = _token.split('.');
        this.header = JSON.parse(
          Buffer.from(parts[0], 'base64').toString('utf8'),
        );
        this.content = JSON.parse(
          Buffer.from(parts[1], 'base64').toString('utf8'),
        );
        this.signature = Buffer.from(parts[2], 'base64');
        this.signed = `${parts[0]}.${parts[1]}`;
      } catch {
        this.content = { exp: 0 } as JwtContent;
      }
    }
  }

  /**
   * The raw JWT string. Matches keycloak-connect's `token.token` property.
   */
  get token(): string {
    return this._token;
  }

  /**
   * Check if the token has a specific role.
   * Matches keycloak-connect's Token.hasRole() logic:
   * - "realm:roleName" checks realm_access.roles
   * - "clientId:roleName" checks resource_access[clientId].roles
   * - "roleName" checks resource_access[this.clientId].roles
   */
  hasRole(name: string): boolean {
    if (!this.clientId) {
      return false;
    }

    const parts = name.split(':');

    if (parts.length === 1) {
      // No prefix — check the default client's resource_access
      return this.hasApplicationRole(this.clientId, parts[0]);
    }

    if (parts[0] === 'realm') {
      return this.hasRealmRole(parts[1]);
    }

    return this.hasApplicationRole(parts[0], parts[1]);
  }

  /**
   * Check if the token has a realm-level role.
   */
  hasRealmRole(roleName: string): boolean {
    const realmAccess = this.content.realm_access;
    if (!realmAccess || !realmAccess.roles) {
      return false;
    }
    return realmAccess.roles.indexOf(roleName) >= 0;
  }

  /**
   * Check if the token has an application/client-level role.
   */
  hasApplicationRole(clientId: string, roleName: string): boolean {
    const resourceAccess = this.content.resource_access;
    if (!resourceAccess) {
      return false;
    }
    const appRoles = resourceAccess[clientId];
    if (!appRoles) {
      return false;
    }
    return appRoles.roles.indexOf(roleName) >= 0;
  }

  /**
   * Check if the token has a specific permission (for UMA/resource server).
   * Matches keycloak-connect's Token.hasPermission() semantics:
   * - If matching resource found with no scope requested, returns true.
   * - If matching resource found with scope requested and scopes array
   *   exists with entries but does NOT include the scope, returns false.
   * - If matching resource found with scope requested and scopes array
   *   is empty or absent, returns true (permission is granted without scope restriction).
   */
  hasPermission(resource: string, scope?: string): boolean {
    const permissions = this.content.authorization
      ? this.content.authorization.permissions
      : undefined;

    if (!permissions) {
      return false;
    }

    for (let i = 0; i < permissions.length; i++) {
      const permission = permissions[i];

      if (permission.rsid === resource || permission.rsname === resource) {
        if (scope) {
          if (permission.scopes && permission.scopes.length > 0) {
            if (!permission.scopes.includes(scope)) {
              return false;
            }
          }
        }
        return true;
      }
    }

    return false;
  }

  /**
   * Check if the token is expired.
   * Matches keycloak-connect's behavior: exp=0 is considered expired.
   */
  isExpired(): boolean {
    return this.content.exp * 1000 < Date.now();
  }

  /**
   * Get the raw JWT string.
   */
  toString(): string {
    return this._token;
  }
}
