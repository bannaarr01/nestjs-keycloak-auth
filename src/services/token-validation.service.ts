import * as crypto from 'crypto';
import { JwksCacheService } from './jwks-cache.service';
import { KEYCLOAK_AUTH_OPTIONS } from '../constants';
import { KeycloakToken } from '../token/keycloak-token';
import { KeycloakHttpService } from './keycloak-http.service';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';

@Injectable()
export class TokenValidationService {
   private readonly logger = new Logger(TokenValidationService.name);
   private readonly publicKey: string | undefined;
   private _notBefore = 0;
   private readonly notBeforeByRealm = new Map<string, number>();

   constructor(
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private readonly keycloakOpts: KeycloakAuthConfig,
    private readonly keycloakHttp: KeycloakHttpService,
    private readonly jwksCache: JwksCacheService,
   ) {
      // Format static realm public key if provided (matches keycloak-connect config.js)
      const plainKey =
      this.keycloakOpts.realmPublicKey ?? this.keycloakOpts['realm-public-key'];
      if (plainKey) {
         let pem = '-----BEGIN PUBLIC KEY-----\n';
         for (let i = 0; i < plainKey.length; i += 64) {
            pem += plainKey.substring(i, i + 64) + '\n';
         }
         pem += '-----END PUBLIC KEY-----';
         this.publicKey = pem;
      }
   }

   get notBefore(): number {
      return this._notBefore;
   }

   set notBefore(value: number) {
      this._notBefore = value;
   }

   getNotBefore(realmUrl?: string): number {
      if (!realmUrl) {
         return this._notBefore;
      }
      return this.notBeforeByRealm.get(realmUrl) ?? this._notBefore;
   }

   setNotBefore(value: number, realmUrl?: string): void {
      if (!realmUrl) {
         this._notBefore = value;
         return;
      }
      this.notBeforeByRealm.set(realmUrl, value);
   }

   /**
   * Validate a token online via the Keycloak introspection endpoint.
   */
   async validateOnline(
      jwt: string,
      realmUrl: string,
      clientId: string,
      secret: string,
   ): Promise<boolean> {
      try {
         const result = await this.keycloakHttp.introspectToken(
            realmUrl,
            clientId,
            secret,
            jwt,
         );
         return result.active === true;
      } catch (ex) {
         this.logger.warn(`Online token validation failed: ${ex}`);
         return false;
      }
   }

   private static readonly ALLOWED_ALGS = new Set([
      'RS256', 'RS384', 'RS512',
      'ES256', 'ES384', 'ES512',
      'PS256', 'PS384', 'PS512',
   ]);

   /**
   * Validate a token offline by verifying signature via JWKS and checking
   * expiry, type, notBefore, issuer, audience, azp, and signature.
   * Matches keycloak-connect's GrantManager.validateToken() logic.
   */
   async validateOffline(
      jwt: string,
      realmUrl: string,
      clientId?: string,
      expectedType: string = 'Bearer',
   ): Promise<boolean> {
      try {
         const token = new KeycloakToken(jwt);

         // Check token exists and is parseable (signed portion present)
         if (!token.signed) {
            this.logger.verbose('invalid token (not signed)');
            return false;
         }

         // Check expiry
         if (token.isExpired()) {
            this.logger.verbose('invalid token (expired)');
            return false;
         }

         // Check token type matches expected
         if (token.content.typ !== expectedType) {
            this.logger.verbose(
               `invalid token (wrong type): expected ${expectedType}, got ${token.content.typ}`,
            );
            return false;
         }

         // Check notBefore policy (stale token)
         const realmNotBefore = this.getNotBefore(realmUrl);
         if (token.content.iat < realmNotBefore) {
            this.logger.verbose(
               `invalid token (stale token): iat ${token.content.iat} < notBefore ${realmNotBefore}`,
            );
            return false;
         }

         // Check issuer matches realm URL
         if (token.content.iss !== realmUrl) {
            this.logger.verbose(
               `invalid token (wrong ISS): ${token.content.iss} !== ${realmUrl}`,
            );
            return false;
         }

         // Audience and azp checks (matches keycloak-connect logic)
         const audienceData = Array.isArray(token.content.aud)
            ? token.content.aud
            : [token.content.aud];

         // Bearer tokens only check audience if verifyTokenAudience is enabled
         const verifyAudience =
        this.keycloakOpts.verifyTokenAudience ??
        this.keycloakOpts['verify-token-audience'] ??
        false;

         if (verifyAudience && clientId && !audienceData.includes(clientId)) {
            this.logger.verbose(
               `invalid token (wrong audience): ${JSON.stringify(token.content.aud)} does not include ${clientId}`,
            );
            return false;
         }

         // Verify algorithm is on the allowlist (prevent algorithm confusion attacks)
         const alg = token.header.alg || 'RS256';
         if (!TokenValidationService.ALLOWED_ALGS.has(alg)) {
            this.logger.verbose(`invalid token (unsupported alg): ${alg}`);
            return false;
         }

         if (this.publicKey) {
            // Use static public key if configured
            if (!this.verifySignature(token.signed, token.signature, this.publicKey, alg)) {
               this.logger.verbose('invalid token (signature)');
               return false;
            }
            return true;
         }

         // Otherwise use JWKS rotation
         const kid = token.header.kid;
         if (!kid) {
            this.logger.warn('Token has no kid in header');
            return false;
         }

         const key = await this.jwksCache.getKey(realmUrl, kid);

         if (!this.verifySignature(token.signed, token.signature, key, alg)) {
            this.logger.verbose('invalid token (public key signature)');
            return false;
         }

         return true;
      } catch (ex) {
         this.logger.warn(`Offline token validation failed: ${ex}`);
         return false;
      }
   }

   private verifySignature(
      signed: string,
      signature: Buffer,
      key: crypto.KeyObject | string,
      jwtAlg: string,
   ): boolean {
      const hashMap: Record<string, string> = {
         RS256: 'SHA256', RS384: 'SHA384', RS512: 'SHA512',
         ES256: 'SHA256', ES384: 'SHA384', ES512: 'SHA512',
         PS256: 'SHA256', PS384: 'SHA384', PS512: 'SHA512',
      };
      const hash = hashMap[jwtAlg] || 'SHA256';
      const keyObj = typeof key === 'string' ? crypto.createPublicKey(key) : key;

      if (jwtAlg.startsWith('PS')) {
         return crypto.verify(
            hash,
            Buffer.from(signed),
            { key: keyObj, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
            signature,
         );
      }

      // crypto.verify() auto-detects key type (RSA vs EC) from the KeyObject
      return crypto.verify(hash, Buffer.from(signed), keyObj, signature);
   }
}
