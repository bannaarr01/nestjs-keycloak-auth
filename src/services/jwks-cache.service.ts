import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import { KeycloakHttpService } from './keycloak-http.service';
import { CachedJwks, JwksKey } from '../interface/jwks.interface';

@Injectable()
export class JwksCacheService {
  private readonly logger = new Logger(JwksCacheService.name);
  private readonly cache = new Map<string, CachedJwks>();
  private minTimeBetweenRequestsMs = 10000; // 10 seconds default

  constructor(private readonly keycloakHttp: KeycloakHttpService) {}

  /**
   * Set the minimum time between JWKS requests (for rate limiting).
   */
  setMinTimeBetweenRequests(ms: number): void {
    this.minTimeBetweenRequestsMs = ms;
  }

  /**
   * Get the public key for a given realm URL and key ID.
   * Fetches JWKS if not cached, or if the kid is not found and rate limit allows.
   */
  async getKey(realmUrl: string, kid: string): Promise<crypto.KeyObject> {
    let cached = this.cache.get(realmUrl);

    // First fetch
    if (!cached) {
      cached = await this.fetchAndCache(realmUrl);
    }

    // Try to find the key
    let jwk = cached.keys.get(kid);

    // Key not found — may be key rotation, try refetching if allowed
    if (!jwk) {
      const now = Date.now();
      if (now - cached.fetchedAt >= this.minTimeBetweenRequestsMs) {
        this.logger.verbose(
          `Key '${kid}' not found, refetching JWKS for ${realmUrl}`,
        );
        cached = await this.fetchAndCache(realmUrl);
        jwk = cached.keys.get(kid);
      }
    }

    if (!jwk) {
      throw new Error(`Key '${kid}' not found in JWKS for realm: ${realmUrl}`);
    }

    return crypto.createPublicKey({
      key: jwk as crypto.JsonWebKey,
      format: 'jwk',
    });
  }

  private async fetchAndCache(realmUrl: string): Promise<CachedJwks> {
    const response = await this.keycloakHttp.fetchJwks(realmUrl);
    const keys = new Map<string, JwksKey>();

    for (const key of response.keys) {
      if (key.kid) {
        keys.set(key.kid, key);
      }
    }

    const cached: CachedJwks = { keys, fetchedAt: Date.now() };
    this.cache.set(realmUrl, cached);
    return cached;
  }
}
