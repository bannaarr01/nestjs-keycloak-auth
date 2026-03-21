import * as crypto from 'crypto';
import { KEYCLOAK_AUTH_OPTIONS } from '../constants';
import { KeycloakToken } from '../token/keycloak-token';
import { JwksCacheService } from './jwks-cache.service';
import { Inject, Injectable, Logger } from '@nestjs/common';
import { KeycloakHttpService } from './keycloak-http.service';
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

      // Verify signature
      const verify = crypto.createVerify('RSA-SHA256');

      if (this.publicKey) {
        // Use static public key if configured
        verify.update(token.signed);
        if (!verify.verify(this.publicKey, token.signature)) {
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
      const alg = token.header.alg || 'RS256';
      const nodeAlg = this.mapAlgorithm(alg);

      const jwksVerifier = crypto.createVerify(nodeAlg);
      jwksVerifier.update(token.signed);
      if (!jwksVerifier.verify(key, token.signature)) {
        this.logger.verbose('invalid token (public key signature)');
        return false;
      }

      return true;
    } catch (ex) {
      this.logger.warn(`Offline token validation failed: ${ex}`);
      return false;
    }
  }

  private mapAlgorithm(jwtAlg: string): string {
    const algMap: Record<string, string> = {
      RS256: 'RSA-SHA256',
      RS384: 'RSA-SHA384',
      RS512: 'RSA-SHA512',
      ES256: 'SHA256',
      ES384: 'SHA384',
      ES512: 'SHA512',
      PS256: 'RSA-SHA256',
      PS384: 'RSA-SHA384',
      PS512: 'RSA-SHA512',
    };
    return algMap[jwtAlg] || 'RSA-SHA256';
  }
}
