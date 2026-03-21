import { parseToken } from '../util';
import { Reflector } from '@nestjs/core';
import { META_PUBLIC } from '../decorators/public.decorator';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { TokenValidationService } from '../services/token-validation.service';
import {
  extractRequestAndAttachCookie,
  useTenantConfig,
} from '../internal.util';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';
import { KeycloakConnectConfig } from '../interface/keycloak-connect-options.interface';
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_COOKIE_DEFAULT,
  KEYCLOAK_INSTANCE,
  KEYCLOAK_MULTITENANT_SERVICE,
  TokenValidation,
} from '../constants';

/**
 * An authentication guard. Will return a 401 unauthorized when it is unable to
 * verify the JWT token or Bearer header is missing.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  private readonly reflector = new Reflector();

  constructor(
    @Inject(KEYCLOAK_INSTANCE)
    private singleTenant: ResolvedTenantConfig,
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private keycloakOpts: KeycloakConnectConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private multiTenant: KeycloakMultiTenantService,
    private tokenValidation: TokenValidationService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);

    // Extract request/response
    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = await extractRequestAndAttachCookie(context, cookieKey);

    // if is not an HTTP request ignore this guard
    if (!request) {
      return true;
    }

    const jwt = this.extractJwt(request.headers);
    const isJwtEmpty = jwt === null || jwt === undefined;

    // Not a public route, require jwt
    if (!isPublic && isJwtEmpty) {
      this.logger.verbose('Empty jwt, unauthorized');
      throw new UnauthorizedException();
    }

    // Public route, no jwt sent
    if (isPublic && isJwtEmpty) {
      return true;
    }

    this.logger.verbose('Validating jwt', { jwt });

    const tenantConfig = await useTenantConfig(
      request,
      jwt,
      this.singleTenant,
      this.multiTenant,
      this.keycloakOpts,
    );
    const isValidToken = await this.validateToken(tenantConfig, jwt);

    if (isValidToken) {
      // Attach user info object
      request.user = parseToken(jwt);
      // Attach raw access token JWT extracted from bearer/cookie
      request.accessToken = jwt;

      this.logger.verbose('User authenticated', { user: request.user });
      return true;
    }

    // Valid token should return, this time we warn
    if (isPublic) {
      this.logger.warn('A jwt token was retrieved but failed validation.', {
        jwt,
      });
      return true;
    }

    throw new UnauthorizedException();
  }

  private async validateToken(tenantConfig: ResolvedTenantConfig, jwt: string) {
    const tokenValidationMethod =
      this.keycloakOpts.tokenValidation || TokenValidation.ONLINE;

    this.logger.verbose(
      `Using token validation method: ${tokenValidationMethod.toUpperCase()}`,
    );

    try {
      switch (tokenValidationMethod) {
        case TokenValidation.ONLINE:
          return await this.tokenValidation.validateOnline(
            jwt,
            tenantConfig.realmUrl,
            tenantConfig.clientId,
            tenantConfig.secret,
          );
        case TokenValidation.OFFLINE:
          return await this.tokenValidation.validateOffline(
            jwt,
            tenantConfig.realmUrl,
          );
        case TokenValidation.NONE:
          return true;
        default:
          this.logger.warn(
            `Unknown validation method: ${tokenValidationMethod}`,
          );
          return false;
      }
    } catch (ex) {
      this.logger.warn(`Cannot validate access token: ${ex}`);
    }

    return false;
  }

  private extractJwt(headers: { [key: string]: string }) {
    if (headers && !headers.authorization) {
      this.logger.verbose('No authorization header');
      return null;
    }

    const auth = headers.authorization.split(' ');

    // We only allow bearer
    if (auth[0].toLowerCase() !== 'bearer') {
      this.logger.verbose('No bearer header');
      return null;
    }

    return auth[1];
  }
}
