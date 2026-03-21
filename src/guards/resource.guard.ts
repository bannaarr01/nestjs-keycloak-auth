import { Reflector } from '@nestjs/core';
import { KeycloakToken } from '../token/keycloak-token';
import { META_PUBLIC } from '../decorators/public.decorator';
import { META_RESOURCE } from '../decorators/resource.decorator';
import { KeycloakHttpService } from '../services/keycloak-http.service';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { META_ENFORCER_OPTIONS } from '../decorators/enforcer-options.decorator';
import { KeycloakEnforcerOptions } from '../interface/enforcer-options.interface';
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
} from '@nestjs/common';
import {
  ConditionalScopeFn,
  META_CONDITIONAL_SCOPES,
  META_SCOPES,
} from '../decorators/scopes.decorator';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_COOKIE_DEFAULT,
  KEYCLOAK_INSTANCE,
  KEYCLOAK_MULTITENANT_SERVICE,
  PolicyEnforcementMode,
} from '../constants';

/**
 * This adds a resource guard, which is policy enforcement by default is permissive.
 * Only controllers annotated with `@Resource` and methods with `@Scopes`
 * are handled by this guard.
 */
@Injectable()
export class ResourceGuard implements CanActivate {
  private readonly logger = new Logger(ResourceGuard.name);
  private readonly reflector = new Reflector();

  constructor(
    @Inject(KEYCLOAK_INSTANCE)
    private singleTenant: ResolvedTenantConfig,
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private keycloakOpts: KeycloakConnectConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private multiTenant: KeycloakMultiTenantService,
    private keycloakHttp: KeycloakHttpService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const resource = this.reflector.get<string>(
      META_RESOURCE,
      context.getClass(),
    );
    const explicitScopes =
      this.reflector.get<string[]>(META_SCOPES, context.getHandler()) ?? [];
    const conditionalScopes = this.reflector.get<ConditionalScopeFn>(
      META_CONDITIONAL_SCOPES,
      context.getHandler(),
    );
    const isPublic = this.reflector.getAllAndOverride<boolean>(META_PUBLIC, [
      context.getClass(),
      context.getHandler(),
    ]);
    // EnforcerOptions metadata is read but only `claims` was used for logging;
    // the permission check is now done via UMA grant on the token endpoint.
    this.reflector.getAllAndOverride<KeycloakEnforcerOptions>(
      META_ENFORCER_OPTIONS,
      [context.getClass(), context.getHandler()],
    );

    // Default to permissive
    const policyEnforcementMode =
      this.keycloakOpts.policyEnforcement || PolicyEnforcementMode.PERMISSIVE;
    const shouldAllow =
      policyEnforcementMode === PolicyEnforcementMode.PERMISSIVE;

    // Extract request/response
    const cookieKey = this.keycloakOpts.cookieKey || KEYCLOAK_COOKIE_DEFAULT;
    const [request] = await extractRequestAndAttachCookie(context, cookieKey);

    // if is not an HTTP request ignore this guard
    if (!request) {
      return true;
    }

    if (!request.user && isPublic) {
      this.logger.verbose('Route has no user, and is public, allowed');
      return true;
    }

    const tenantConfig = await useTenantConfig(
      request,
      request.accessToken,
      this.singleTenant,
      this.multiTenant,
      this.keycloakOpts,
    );

    // No resource given, check policy enforcement mode
    if (!resource) {
      if (shouldAllow) {
        this.logger.verbose(
          'Controller has no @Resource defined, request allowed due to policy enforcement',
        );
      } else {
        this.logger.verbose(
          'Controller has no @Resource defined, request denied due to policy enforcement',
        );
      }
      return shouldAllow;
    }

    // Build the required scopes
    let token: KeycloakToken | undefined;
    if (conditionalScopes != null && conditionalScopes != undefined) {
      token = new KeycloakToken(request.accessToken, tenantConfig.clientId);
    }
    const conditionalScopesResult =
      conditionalScopes != null || conditionalScopes != undefined
        ? conditionalScopes(request, token)
        : [];

    const scopes = [...explicitScopes, ...conditionalScopesResult];

    // Attach resolved scopes
    request.scopes = scopes;

    // No scopes given, check policy enforcement mode
    if (!scopes || scopes.length === 0) {
      if (shouldAllow) {
        this.logger.verbose(
          'Route has no @Scope/@ConditionalScopes defined, request allowed due to policy enforcement',
        );
      } else {
        this.logger.verbose(
          'Route has no @Scope/@ConditionalScopes defined, request denied due to policy enforcement',
        );
      }
      return shouldAllow;
    }

    this.logger.verbose(
      `Protecting resource [ ${resource} ] with scopes: [ ${scopes} ]`,
    );

    const user = request.user?.preferred_username ?? 'user';

    // Build permissions
    const permissions = scopes.map((scope) => `${resource}:${scope}`);
    const isAllowed = await this.keycloakHttp.checkPermission(
      tenantConfig.realmUrl,
      tenantConfig.clientId,
      tenantConfig.secret,
      request.accessToken,
      permissions,
    );

    // If statement for verbose logging only
    if (!isAllowed) {
      this.logger.verbose(`Resource [ ${resource} ] denied to [ ${user} ]`);
    } else {
      this.logger.verbose(`Resource [ ${resource} ] granted to [ ${user} ]`);
    }

    return isAllowed;
  }
}
