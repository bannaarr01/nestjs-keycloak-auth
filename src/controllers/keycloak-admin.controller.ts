import { KEYCLOAK_INSTANCE } from '../constants';
import { KeycloakToken } from '../token/keycloak-token';
import { JwksCacheService } from '../services/jwks-cache.service';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { TokenValidationService } from '../services/token-validation.service';
import {
  Body,
  Controller,
  HttpCode,
  Inject,
  Logger,
  Post,
  Res,
} from '@nestjs/common';

interface ServerResponse {
  status(code: number): ServerResponse;
  end(data?: string): void;
  send(data: string): void;
}

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
    private readonly tokenValidation: TokenValidationService,
    private readonly jwksCache: JwksCacheService,
  ) {}

  @Post('k_logout')
  @HttpCode(200)
  async handleLogout(@Body() body: string, @Res() response: ServerResponse) {
    try {
      const token = new KeycloakToken(body);
      if (!token.signed) {
        response.status(400).end('invalid token');
        return;
      }

      if (token.content.action === 'LOGOUT') {
        const sessionIDs = token.content.adapterSessionIds;
        if (!sessionIDs) {
          // Global notBefore update
          this.tokenValidation.notBefore = token.content.notBefore;
          this.logger.log(
            `Admin logout: notBefore set to ${token.content.notBefore}`,
          );
        }
        response.send('ok');
      } else {
        response.status(400).end();
      }
    } catch (err) {
      this.logger.warn(`Admin logout failed: ${err}`);
      response.status(400).end(err instanceof Error ? err.message : 'error');
    }
  }

  @Post('k_push_not_before')
  @HttpCode(200)
  async handlePushNotBefore(
    @Body() body: string,
    @Res() response: ServerResponse,
  ) {
    try {
      const token = new KeycloakToken(body);
      if (!token.signed) {
        response.status(400).end('invalid token');
        return;
      }

      if (token.content.action === 'PUSH_NOT_BEFORE') {
        this.tokenValidation.notBefore = token.content.notBefore;
        this.logger.log(
          `Push not-before: notBefore set to ${token.content.notBefore}`,
        );
        response.send('ok');
      } else {
        response.status(400).end();
      }
    } catch (err) {
      this.logger.warn(`Push not-before failed: ${err}`);
      response.status(400).end(err instanceof Error ? err.message : 'error');
    }
  }
}
