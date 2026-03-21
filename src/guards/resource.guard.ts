import { Reflector } from '@nestjs/core';
import { KeycloakToken } from '../token/keycloak-token';
import { META_PUBLIC } from '../decorators/public.decorator';
import { META_RESOURCE } from '../decorators/resource.decorator';
import { KeycloakHttpService } from '../services/keycloak-http.service';
import { extractRequest, useTenantConfig } from '../internal.util';
import { KeycloakPermission } from '../interface/keycloak-grant.interface';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { KeycloakEnforcerOptions } from '../interface/enforcer-options.interface';
import { META_ENFORCER_OPTIONS } from '../decorators/enforcer-options.decorator';
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
    const enforcerOptions =
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
    const [request] = extractRequest(context);

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

    // Build permissions as "resource:scope" pairs
    const permissions = scopes.map((scope) => `${resource}:${scope}`);

    // Local permission check: if the access token already contains the
    // required permissions, allow immediately without a server round-trip
    // (matches keycloak-connect enforcer.js behavior)
    if (request.accessToken) {
      const accessToken =
        token ?? new KeycloakToken(request.accessToken, tenantConfig.clientId);

      const allPermissionsGranted = scopes.every((scope) =>
        accessToken.hasPermission(resource, scope),
      );

      if (allPermissionsGranted) {
        this.logger.verbose(
          `Resource [ ${resource} ] granted to [ ${user} ] (local token check)`,
        );
        return true;
      }
    }

    // Server-side permission check
    const claims = this.resolveClaims(request, enforcerOptions);
    const responseMode = enforcerOptions?.response_mode ?? 'permissions';
    const audience =
      enforcerOptions?.resource_server_id ?? tenantConfig.clientId;
    const isPublicClient = tenantConfig.isPublic;

    if (responseMode === 'permissions') {
      // Permissions mode: get permission list from server, validate locally
      try {
        const serverPermissions = (await this.keycloakHttp.checkPermission(
          tenantConfig.realmUrl,
          tenantConfig.clientId,
          tenantConfig.secret,
          request.accessToken,
          permissions,
          {
            claims: claims || undefined,
            response_mode: 'permissions',
            audience,
            isPublic: isPublicClient,
          },
        )) as KeycloakPermission[];

        const isAllowed = this.validatePermissionsLocally(
          serverPermissions,
          resource,
          scopes,
        );

        if (isAllowed) {
          // Attach permissions to request (matches original enforcer.js)
          request.permissions = serverPermissions;
          this.logger.verbose(
            `Resource [ ${resource} ] granted to [ ${user} ]`,
          );
        } else {
          this.logger.verbose(`Resource [ ${resource} ] denied to [ ${user} ]`);
        }
        return isAllowed;
      } catch {
        this.logger.verbose(
          `Resource [ ${resource} ] denied to [ ${user} ] (permissions check failed)`,
        );
        return false;
      }
    }

    if (responseMode === 'token') {
      // Token mode: get a new grant with permissions, validate locally
      try {
        const grant = (await this.keycloakHttp.checkPermission(
          tenantConfig.realmUrl,
          tenantConfig.clientId,
          tenantConfig.secret,
          request.accessToken,
          permissions,
          {
            claims: claims || undefined,
            response_mode: 'token',
            audience,
            isPublic: isPublicClient,
          },
        )) as { access_token: string };

        const grantToken = new KeycloakToken(
          grant.access_token,
          tenantConfig.clientId,
        );
        const isAllowed = scopes.every((scope) =>
          grantToken.hasPermission(resource, scope),
        );

        if (isAllowed) {
          this.logger.verbose(
            `Resource [ ${resource} ] granted to [ ${user} ]`,
          );
        } else {
          this.logger.verbose(`Resource [ ${resource} ] denied to [ ${user} ]`);
        }
        return isAllowed;
      } catch {
        this.logger.verbose(
          `Resource [ ${resource} ] denied to [ ${user} ] (token check failed)`,
        );
        return false;
      }
    }

    // Default: decision mode
    const isAllowed = (await this.keycloakHttp.checkPermission(
      tenantConfig.realmUrl,
      tenantConfig.clientId,
      tenantConfig.secret,
      request.accessToken,
      permissions,
      {
        claims: claims || undefined,
        response_mode: 'decision',
        audience,
        isPublic: isPublicClient,
      },
    )) as boolean;

    // If statement for verbose logging only
    if (!isAllowed) {
      this.logger.verbose(`Resource [ ${resource} ] denied to [ ${user} ]`);
    } else {
      this.logger.verbose(`Resource [ ${resource} ] granted to [ ${user} ]`);
    }

    return isAllowed;
  }

  /**
   * Validate server-returned permissions against expected resource:scope pairs.
   * Matches keycloak-connect enforcer.js handlePermissions logic.
   */
  private validatePermissionsLocally(
    serverPermissions: KeycloakPermission[],
    resource: string,
    scopes: string[],
  ): boolean {
    if (!serverPermissions || serverPermissions.length === 0) {
      return false;
    }

    for (const scope of scopes) {
      let found = false;

      for (const permission of serverPermissions) {
        if (permission.rsid === resource || permission.rsname === resource) {
          if (scope) {
            if (permission.scopes && permission.scopes.length > 0) {
              if (!permission.scopes.includes(scope)) {
                return false;
              }
              found = true;
              break;
            }
            return false;
          }
          found = true;
          break;
        }
      }

      if (!found) {
        return false;
      }
    }

    return true;
  }

  private resolveClaims(
    request: Record<string, unknown>,
    enforcerOptions?: KeycloakEnforcerOptions,
  ): Record<string, unknown> | undefined {
    if (enforcerOptions) {
      return enforcerOptions.claims?.(request);
    }

    const requestHeaders = request.headers as
      | Record<string, string | string[] | undefined>
      | undefined;
    const userAgentRaw = requestHeaders?.['user-agent'];
    const userAgent = Array.isArray(userAgentRaw)
      ? userAgentRaw[0]
      : userAgentRaw;
    const httpUri =
      (typeof request.url === 'string' && request.url) ||
      (typeof request.originalUrl === 'string' && request.originalUrl) ||
      '';

    this.logger.verbose(
      `Enforcing claims, http.uri: ${httpUri}, user.agent: ${userAgent ?? ''}`,
    );

    return {
      'http.uri': [httpUri],
      'user.agent': [userAgent ?? ''],
    };
  }
}
