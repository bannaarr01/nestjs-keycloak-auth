import * as crypto from 'crypto';
import { JwksCacheService } from './jwks-cache.service';
import { KeycloakToken } from '../token/keycloak-token';
import { ServerRequest } from '../interface/server.interface';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { BackchannelLogoutService } from './backchannel-logout.service';
import { TokenValidationService } from './token-validation.service';
import { KeycloakAdminError, KeycloakConfigError } from '../errors';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { KeycloakMultiTenantService } from './keycloak-multitenant.service';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';
import { KEYCLOAK_INSTANCE, KEYCLOAK_AUTH_OPTIONS, KEYCLOAK_MULTITENANT_SERVICE } from '../constants';

/**
 * Encapsulates all business logic for Keycloak admin callbacks:
 * push-not-before policy and OIDC back-channel logout.
 */
@Injectable()
export class KeycloakAdminService {
   private readonly logger = new Logger(KeycloakAdminService.name);

   constructor(
    @Inject(KEYCLOAK_INSTANCE)
    private readonly tenantConfig: ResolvedTenantConfig,
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private readonly keycloakOpts: KeycloakAuthConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private readonly multiTenant: KeycloakMultiTenantService,
    private readonly tokenValidation: TokenValidationService,
    private readonly jwksCache: JwksCacheService,
    private readonly backchannelLogoutService: BackchannelLogoutService,
   ) {}

   /**
   * Process a push-not-before admin callback.
   * Verifies the token signature and updates the not-before policy.
   */
   async processPushNotBefore(
      body: unknown,
      request: ServerRequest,
   ): Promise<void> {
      const payload = this.extractAdminPayload(body, request);
      if (!payload) {
         throw new KeycloakConfigError('invalid token');
      }

      const token = new KeycloakToken(payload);
      if (!token.signed) {
         throw new KeycloakConfigError('invalid token');
      }

      const tenantConfig = await this.resolveTenantConfig(request, token);
      await this.verifySignature(token, tenantConfig.realmUrl);

      if (token.isExpired()) {
         throw new KeycloakAdminError('admin request failed: token expired');
      }

      if (token.content.action !== 'PUSH_NOT_BEFORE') {
         throw new KeycloakConfigError('unsupported action');
      }

      if (typeof token.content.notBefore !== 'number') {
         throw new KeycloakConfigError('invalid token');
      }

      this.tokenValidation.setNotBefore(
         token.content.notBefore,
         tenantConfig.realmUrl,
      );
      this.logger.log(
         `Push not-before (${tenantConfig.realm}): notBefore set to ${token.content.notBefore}`,
      );
   }

   /**
   * Process an OIDC back-channel logout token.
   * Verifies signature, validates claims, and revokes the session/user.
   */
   async processBackchannelLogout(
      body: unknown,
      request: ServerRequest,
   ): Promise<void> {
      const logoutTokenRaw = this.extractLogoutToken(body);
      if (!logoutTokenRaw) {
         throw new KeycloakConfigError('invalid logout token');
      }

      const token = new KeycloakToken(logoutTokenRaw);
      if (!token.signed) {
         throw new KeycloakConfigError('invalid logout token');
      }

      const tenantConfig = await this.resolveTenantConfig(request, token);
      await this.verifySignature(token, tenantConfig.realmUrl);

      if (token.isExpired()) {
         throw new KeycloakAdminError('admin request failed: logout token expired');
      }

      // Validate typ is "logout+jwt" or "JWT" (per OIDC Back-Channel Logout spec)
      const typ = token.header?.typ;
      if (typ !== 'logout+jwt' && typ !== 'JWT') {
         throw new KeycloakConfigError('invalid logout token type');
      }

      // Validate events claim contains back-channel logout event
      const events = token.content?.events;
      if (
         !events ||
        typeof events !== 'object' ||
        !('http://schemas.openid.net/event/backchannel-logout' in events)
      ) {
         throw new KeycloakConfigError('missing backchannel-logout event');
      }

      const sid =
        typeof token.content.sid === 'string'
           ? token.content.sid
           : undefined;
      const sub =
        typeof token.content.sub === 'string'
           ? token.content.sub
           : undefined;

      if (!sid && !sub) {
         throw new KeycloakConfigError('logout token must contain sid or sub');
      }

      this.backchannelLogoutService.revoke(sid, sub);
      this.logger.log(
         `Back-channel logout processed: sid=${sid || 'n/a'}, sub=${sub || 'n/a'}`,
      );
   }

   private extractAdminPayload(
      body: unknown,
      request: ServerRequest,
   ): string | null {
      if (typeof body === 'string' && body.trim() !== '') {
         return body.trim();
      }

      if (Buffer.isBuffer(body) && body.length > 0) {
         return body.toString('utf8').trim();
      }

      if (typeof request.rawBody === 'string' && request.rawBody.trim() !== '') {
         return request.rawBody.trim();
      }

      if (Buffer.isBuffer(request.rawBody) && request.rawBody.length > 0) {
         return request.rawBody.toString('utf8').trim();
      }

      if (body && typeof body === 'object') {
         const map = body as Record<string, unknown>;
         if (typeof map.token === 'string' && map.token.trim() !== '') {
            return map.token.trim();
         }

         // URL-encoded bodies can be parsed as { "<jwt>": "" }.
         const keys = Object.keys(map);
         if (keys.length === 1 && map[keys[0]] === '') {
            return keys[0];
         }
      }

      return null;
   }

   private extractLogoutToken(body: unknown): string | null {
      if (body && typeof body === 'object') {
         const map = body as Record<string, unknown>;
         if (
            typeof map.logout_token === 'string' &&
          map.logout_token.trim() !== ''
         ) {
            return map.logout_token.trim();
         }
      }
      return null;
   }

   private static readonly ALLOWED_ALGS = new Set([
      'RS256', 'RS384', 'RS512',
      'ES256', 'ES384', 'ES512',
      'PS256', 'PS384', 'PS512',
   ]);

   private async verifySignature(
      token: KeycloakToken,
      realmUrl: string,
   ): Promise<void> {
      const kid =
      token.header && typeof token.header.kid === 'string'
         ? token.header.kid
         : undefined;
      if (!kid) {
         throw new KeycloakAdminError('admin request failed: missing token kid');
      }

      let key: crypto.KeyObject;
      try {
         key = await this.jwksCache.getKey(realmUrl, kid);
      } catch (err) {
         throw new KeycloakAdminError(
            `failed to load public key to verify token. Reason: ${err}`,
         );
      }

      const alg =
      token.header && typeof token.header.alg === 'string'
         ? token.header.alg
         : 'RS256';

      if (!KeycloakAdminService.ALLOWED_ALGS.has(alg)) {
         throw new KeycloakAdminError(
            `admin request failed: unsupported token algorithm: ${alg}`,
         );
      }

      if (!this.verifyTokenSignature(token.signed, token.signature, key, alg)) {
         throw new KeycloakAdminError(
            'admin request failed: invalid token (signature)',
         );
      }
   }

   private verifyTokenSignature(
      signed: string,
      signature: Buffer,
      key: crypto.KeyObject,
      jwtAlg: string,
   ): boolean {
      const hashMap: Record<string, string> = {
         RS256: 'SHA256', RS384: 'SHA384', RS512: 'SHA512',
         ES256: 'SHA256', ES384: 'SHA384', ES512: 'SHA512',
         PS256: 'SHA256', PS384: 'SHA384', PS512: 'SHA512',
      };
      const hash = hashMap[jwtAlg] || 'SHA256';

      if (jwtAlg.startsWith('PS')) {
         return crypto.verify(
            hash,
            Buffer.from(signed),
            { key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
            signature,
         );
      }

      // crypto.verify() auto-detects key type (RSA vs EC) from the KeyObject
      return crypto.verify(hash, Buffer.from(signed), key, signature);
   }

   private async resolveTenantConfig(
      request: ServerRequest,
      token: KeycloakToken,
   ): Promise<ResolvedTenantConfig> {
      if (this.keycloakOpts.multiTenant?.realmResolver) {
         try {
            const resolvedRealm =
          this.keycloakOpts.multiTenant.realmResolver(request);
            const realm =
          resolvedRealm instanceof Promise
             ? await resolvedRealm
             : resolvedRealm;
            if (!realm) {
               throw new KeycloakConfigError(
                  'admin request failed: realm resolver returned an empty realm',
               );
            }
            return await this.multiTenant.get(realm, request);
         } catch (err) {
            if (err instanceof KeycloakConfigError) {
               throw err;
            }
            throw new KeycloakConfigError(
               `admin request failed: cannot resolve tenant config. Reason: ${err}`,
            );
         }
      }

      // Single-tenant configured realm: use static tenant config.
      if (this.keycloakOpts.realm) {
         return this.tenantConfig;
      }

      // Do NOT fall back to the token's iss claim — an attacker from a
      // different realm on the same Keycloak server could forge admin
      // callbacks by setting iss to their own realm.
      throw new KeycloakConfigError(
         'admin request failed: cannot resolve realm — configure realm or multiTenant.realmResolver for admin callbacks',
      );
   }
}
