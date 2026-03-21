import * as crypto from 'crypto';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_INSTANCE,
  KEYCLOAK_MULTITENANT_SERVICE,
} from '../constants';
import { KeycloakToken } from '../token/keycloak-token';
import { JwksCacheService } from '../services/jwks-cache.service';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { TokenValidationService } from '../services/token-validation.service';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';
import {
  Body,
  Controller,
  HttpCode,
  Inject,
  Logger,
  Post,
  Req,
  Res,
} from '@nestjs/common';

interface ServerResponse {
  status(code: number): ServerResponse;
  end(data?: string): void;
  send(data: string): void;
}

interface ServerRequest {
  body?: unknown;
  rawBody?: unknown;
  [key: string]: unknown;
}

class AdminAuthError extends Error {}
class AdminConfigError extends Error {}

/**
 * Handles Keycloak admin callbacks (k_logout and k_push_not_before).
 * Matches keycloak-connect's admin.js middleware behavior.
 *
 * These endpoints are called by the Keycloak server when an admin
 * triggers session invalidation or pushes a not-before policy from
 * the Keycloak admin console.
 */
@Controller()
export class KeycloakAdminController {
  private readonly logger = new Logger(KeycloakAdminController.name);

  constructor(
    @Inject(KEYCLOAK_INSTANCE)
    private readonly tenantConfig: ResolvedTenantConfig,
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private readonly keycloakOpts: KeycloakConnectConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private readonly multiTenant: KeycloakMultiTenantService,
    private readonly tokenValidation: TokenValidationService,
    private readonly jwksCache: JwksCacheService,
  ) {}

  @Post('k_logout')
  @HttpCode(200)
  async handleLogout(
    @Body() body: unknown,
    @Req() request: ServerRequest,
    @Res() response: ServerResponse,
  ) {
    try {
      const payload = this.extractAdminPayload(body, request);
      if (!payload) {
        response.status(400).end('invalid token');
        return;
      }

      const token = new KeycloakToken(payload);
      if (!token.signed) {
        response.status(400).end('invalid token');
        return;
      }
      const tenantConfig = await this.resolveTenantConfig(request, token);
      await this.verifyAdminSignature(token, tenantConfig.realmUrl);

      if (token.content.action === 'LOGOUT') {
        const sessionIDs = token.content.adapterSessionIds;
        if (!sessionIDs) {
          if (typeof token.content.notBefore !== 'number') {
            response.status(400).end('invalid token');
            return;
          }
          this.tokenValidation.setNotBefore(
            token.content.notBefore,
            tenantConfig.realmUrl,
          );
          this.logger.log(
            `Admin logout (${tenantConfig.realm}): notBefore set to ${token.content.notBefore}`,
          );
        }
        response.send('ok');
      } else {
        response.status(400).end();
      }
    } catch (err) {
      this.logger.warn(`Admin logout failed: ${err}`);
      const status = err instanceof AdminAuthError ? 401 : 400;
      response.status(status).end(err instanceof Error ? err.message : 'error');
    }
  }

  @Post('k_push_not_before')
  @HttpCode(200)
  async handlePushNotBefore(
    @Body() body: unknown,
    @Req() request: ServerRequest,
    @Res() response: ServerResponse,
  ) {
    try {
      const payload = this.extractAdminPayload(body, request);
      if (!payload) {
        response.status(400).end('invalid token');
        return;
      }

      const token = new KeycloakToken(payload);
      if (!token.signed) {
        response.status(400).end('invalid token');
        return;
      }
      const tenantConfig = await this.resolveTenantConfig(request, token);
      await this.verifyAdminSignature(token, tenantConfig.realmUrl);

      if (token.content.action === 'PUSH_NOT_BEFORE') {
        if (typeof token.content.notBefore !== 'number') {
          response.status(400).end('invalid token');
          return;
        }
        this.tokenValidation.setNotBefore(
          token.content.notBefore,
          tenantConfig.realmUrl,
        );
        this.logger.log(
          `Push not-before (${tenantConfig.realm}): notBefore set to ${token.content.notBefore}`,
        );
        response.send('ok');
      } else {
        response.status(400).end();
      }
    } catch (err) {
      this.logger.warn(`Push not-before failed: ${err}`);
      const status = err instanceof AdminAuthError ? 401 : 400;
      response.status(status).end(err instanceof Error ? err.message : 'error');
    }
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

  private async verifyAdminSignature(
    token: KeycloakToken,
    realmUrl: string,
  ): Promise<void> {
    const kid =
      token.header && typeof token.header.kid === 'string'
        ? token.header.kid
        : undefined;
    if (!kid) {
      throw new AdminAuthError('admin request failed: missing token kid');
    }

    let key: crypto.KeyObject;
    try {
      key = await this.jwksCache.getKey(realmUrl, kid);
    } catch (err) {
      throw new AdminAuthError(
        `failed to load public key to verify token. Reason: ${err}`,
      );
    }

    const alg =
      token.header && typeof token.header.alg === 'string'
        ? token.header.alg
        : 'RS256';
    const verifier = crypto.createVerify(this.mapAlgorithm(alg));
    verifier.update(token.signed);

    if (!verifier.verify(key, token.signature)) {
      throw new AdminAuthError(
        'admin request failed: invalid token (signature)',
      );
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
          throw new AdminConfigError(
            'admin request failed: realm resolver returned an empty realm',
          );
        }
        return await this.multiTenant.get(realm, request);
      } catch (err) {
        if (err instanceof AdminConfigError) {
          throw err;
        }
        throw new AdminConfigError(
          `admin request failed: cannot resolve tenant config. Reason: ${err}`,
        );
      }
    }

    // Single-tenant configured realm: use static tenant config.
    if (this.keycloakOpts.realm) {
      return this.tenantConfig;
    }

    // Multi-tenant fallback by issuer realm when available in callback token.
    const issuer =
      token.content && typeof token.content.iss === 'string'
        ? token.content.iss
        : undefined;
    const issuerRealm = issuer?.split('/').pop();
    if (issuerRealm) {
      return await this.multiTenant.get(issuerRealm, request);
    }

    throw new AdminConfigError(
      'admin request failed: cannot resolve realm for admin callback in multi-tenant mode',
    );
  }
}
