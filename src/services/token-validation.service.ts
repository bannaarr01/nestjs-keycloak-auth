import * as crypto from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { KeycloakToken } from '../token/keycloak-token';
import { JwksCacheService } from './jwks-cache.service';
import { KeycloakHttpService } from './keycloak-http.service';

@Injectable()
export class TokenValidationService {
  private readonly logger = new Logger(TokenValidationService.name);

  constructor(
    private readonly keycloakHttp: KeycloakHttpService,
    private readonly jwksCache: JwksCacheService,
  ) {}

  /**
   * Validate a token online via the Keycloak as introspection endpoint.
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
   * Validate a token offline by verifying signature via JWKS and checking expiry/issuer.
   */
  async validateOffline(jwt: string, realmUrl: string): Promise<boolean> {
    try {
      const token = new KeycloakToken(jwt);

      // Check expiry
      if (token.isExpired()) {
        this.logger.verbose('Token is expired');
        return false;
      }

      // Check issuer matches realm URL
      const iss = token.content.iss;
      if (iss && iss !== realmUrl) {
        this.logger.verbose(`Issuer mismatch: ${iss} !== ${realmUrl}`);
        return false;
      }

      // Verify signature
      const kid = token.header.kid;
      if (!kid) {
        this.logger.warn('Token has no kid in header');
        return false;
      }

      const publicKey = await this.jwksCache.getKey(realmUrl, kid);
      const alg = token.header.alg || 'RS256';
      const nodeAlg = this.mapAlgorithm(alg);

      const verifier = crypto.createVerify(nodeAlg);
      verifier.update(token.signed);
      const isValid = verifier.verify(publicKey, token.signature);

      return isValid;
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
