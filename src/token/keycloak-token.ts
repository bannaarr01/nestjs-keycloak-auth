/**
 * Native KeycloakToken class that replaces keycloak-connect's Token.
 * Parses a JWT and provides role/permission checking methods.
 */
export class KeycloakToken {
  readonly header: Record<string, any>;
  readonly content: Record<string, any>;
  readonly signature: Buffer;
  readonly signed: string;

  constructor(
    private readonly token: string,
    private readonly clientId?: string,
  ) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT: expected 3 parts');
    }

    this.header = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8'),
    );
    this.content = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    );
    this.signature = Buffer.from(parts[2], 'base64url');
    this.signed = `${parts[0]}.${parts[1]}`;
  }

  /**
   * Check if the token has a specific role.
   * Matches keycloak-connect's Token.hasRole() logic:
   * - "realm:roleName" checks realm_access.roles
   * - "clientId:roleName" checks resource_access[clientId].roles
   * - "roleName" checks resource_access[this.clientId].roles
   */
  hasRole(name: string): boolean {
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
    if (!realmAccess || !Array.isArray(realmAccess.roles)) {
      return false;
    }
    return realmAccess.roles.includes(roleName);
  }

  /**
   * Check if the token has an application/client-level role.
   */
  hasApplicationRole(clientId: string, roleName: string): boolean {
    const resourceAccess = this.content.resource_access;
    if (!resourceAccess) {
      return false;
    }
    const clientAccess = resourceAccess[clientId];
    if (!clientAccess || !Array.isArray(clientAccess.roles)) {
      return false;
    }
    return clientAccess.roles.includes(roleName);
  }

  /**
   * Check if the token has a specific permission (for UMA/resource server).
   */
  hasPermission(resource: string, scope?: string): boolean {
    const authorization = this.content.authorization;
    if (!authorization || !Array.isArray(authorization.permissions)) {
      return false;
    }
    return authorization.permissions.some((perm: any) => {
      if (perm.rsname !== resource && perm.rsid !== resource) {
        return false;
      }
      if (!scope) {
        return true;
      }
      return Array.isArray(perm.scopes) && perm.scopes.includes(scope);
    });
  }

  /**
   * Check if the token is expired.
   */
  isExpired(): boolean {
    const exp = this.content.exp;
    if (!exp) {
      return false;
    }
    return Math.floor(Date.now() / 1000) >= exp;
  }

  /**
   * Get the raw JWT string.
   */
  toString(): string {
    return this.token;
  }
}
