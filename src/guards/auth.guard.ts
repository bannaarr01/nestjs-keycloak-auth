import { parseToken } from '../util';
import { Reflector } from '@nestjs/core';
import { META_PUBLIC } from '../decorators/public.decorator';
import { META_TOKEN_SCOPES } from '../decorators/token-scopes.decorator';
import { extractRequest, useTenantConfig } from '../internal.util';
import { KeycloakGrantService } from '../services/keycloak-grant.service';
import { BackchannelLogoutService } from '../services/backchannel-logout.service';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { TokenValidationService } from '../services/token-validation.service';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';
import {
   CanActivate,
   ExecutionContext,
   ForbiddenException,
   Inject,
   Injectable,
   Logger,
   UnauthorizedException,
} from '@nestjs/common';
import {
   KEYCLOAK_AUTH_OPTIONS,
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
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private keycloakOpts: KeycloakAuthConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private multiTenant: KeycloakMultiTenantService,
    private tokenValidation: TokenValidationService,
    private keycloakGrant: KeycloakGrantService,
    private backchannelLogout: BackchannelLogoutService,
   ) {}

   async canActivate(context: ExecutionContext): Promise<boolean> {
      const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
         context.getClass(),
         context.getHandler(),
      ]);

      // Extract request/response
      const [request] = extractRequest(context);

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
         // Attach raw access token JWT extracted from bearer
         request.accessToken = jwt;

         // Check back-channel logout revocation
         const sid = request.user?.sid as string | undefined;
         const sub = request.user?.sub as string | undefined;
         if (this.backchannelLogout.isRevoked(sid, sub)) {
            this.logger.verbose('Session or user has been revoked via back-channel logout');
            if (isPublic) {
               request.user = undefined;
               request.accessToken = undefined;
               return true;
            }
            throw new UnauthorizedException();
         }

         // Check @TokenScopes() decorator requirements
         const requiredScopes = this.reflector.getAllAndOverride<string[]>(
            META_TOKEN_SCOPES,
            [context.getClass(), context.getHandler()],
         );
         if (requiredScopes && requiredScopes.length > 0) {
            const scopeClaim = request.user?.scope;
            const grantedScopes = new Set(
               typeof scopeClaim === 'string' ? scopeClaim.split(' ') : [],
            );
            const missing = requiredScopes.filter((s) => !grantedScopes.has(s));
            if (missing.length > 0) {
               this.logger.verbose(
                  `Token missing required scopes: ${missing.join(', ')}`,
               );
               throw new ForbiddenException(
                  `Missing required token scopes: ${missing.join(', ')}`,
               );
            }
         }

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
            try {
               await this.keycloakGrant.createGrant(
                  { access_token: jwt },
                  tenantConfig.realmUrl,
                  tenantConfig.clientId,
               );
            } catch (ex) {
               this.logger.warn(`Cannot validate access token: ${ex}`);
               return false;
            }
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
               tenantConfig.clientId,
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

   private extractJwt(headers: Record<string, string | string[] | undefined>) {
      const authorization = headers?.authorization;
      if (!authorization || typeof authorization !== 'string') {
         this.logger.verbose('No authorization header');
         return null;
      }

      const auth = authorization.split(' ');

      // We only allow bearer
      if (auth[0].toLowerCase() !== 'bearer') {
         this.logger.verbose('No bearer header');
         return null;
      }

      return auth[1];
   }
}
