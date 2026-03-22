import { JwtContent, JwtHeader } from '../interface/jwt.interface';

export { JwtContent, JwtHeader };
export type { JwtPermission } from '../interface/jwt.interface';

/**
 * Native KeycloakToken class that replaces keycloak-connect's Token.
 * Parses a JWT and provides role/permission checking methods.
 */
export class KeycloakToken {
   readonly header: JwtHeader = {} as JwtHeader;
   readonly content: JwtContent = { exp: 0 } as JwtContent;
   readonly signature: Buffer = Buffer.alloc(0);
   readonly signed: string = '';

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
            // defaults already set above
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
      return this.content.realm_access?.roles?.includes(roleName) ?? false;
   }

   /**
   * Check if the token has an application/client-level role.
   */
   hasApplicationRole(clientId: string, roleName: string): boolean {
      return (
         this.content.resource_access?.[clientId]?.roles?.includes(roleName) ??
      false
      );
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
      const match = this.content.authorization?.permissions?.find(
         (p) => p.rsid === resource || p.rsname === resource,
      );

      if (!match) {
         return false;
      }

      // Scope requested and the permission has an explicit scope list that doesn't include it
      if (scope && match.scopes?.length > 0 && !match.scopes.includes(scope)) {
         return false;
      }

      return true;
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
