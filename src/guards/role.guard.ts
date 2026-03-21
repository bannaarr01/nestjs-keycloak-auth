import { Reflector } from '@nestjs/core';
import { KeycloakToken } from '../token/keycloak-token';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { extractRequest, useTenantConfig } from '../internal.util';
import {
  META_ROLE_MATCHING_MODE,
  META_ROLES,
} from '../decorators/roles.decorator';
import { KeycloakMultiTenantService } from '../services/keycloak-multitenant.service';
import { KeycloakAuthConfig } from '../interface/keycloak-auth-options.interface';
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import {
  KEYCLOAK_AUTH_OPTIONS,
  KEYCLOAK_INSTANCE,
  KEYCLOAK_MULTITENANT_SERVICE,
  RoleMatch,
  RoleMerge,
} from '../constants';

/**
 * A permissive type of role guard. Roles are set via `@Roles` decorator.
 * @since 1.1.0
 */
@Injectable()
export class RoleGuard implements CanActivate {
  private readonly logger = new Logger(RoleGuard.name);
  private readonly reflector = new Reflector();

  constructor(
    @Inject(KEYCLOAK_INSTANCE)
    private singleTenant: ResolvedTenantConfig,
    @Inject(KEYCLOAK_AUTH_OPTIONS)
    private keycloakOpts: KeycloakAuthConfig,
    @Inject(KEYCLOAK_MULTITENANT_SERVICE)
    private multiTenant: KeycloakMultiTenantService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roleMerge = this.keycloakOpts.roleMerge
      ? this.keycloakOpts.roleMerge
      : RoleMerge.OVERRIDE;

    const roles: string[] = [];

    const matchingMode = this.reflector.getAllAndOverride<RoleMatch>(
      META_ROLE_MATCHING_MODE,
      [context.getClass(), context.getHandler()],
    );

    if (roleMerge == RoleMerge.ALL) {
      const mergedRoles = this.reflector.getAllAndMerge<string[]>(META_ROLES, [
        context.getClass(),
        context.getHandler(),
      ]);

      if (mergedRoles) {
        roles.push(...mergedRoles);
      }
    } else if (roleMerge == RoleMerge.OVERRIDE) {
      const resultRoles = this.reflector.getAllAndOverride<string[]>(
        META_ROLES,
        [context.getClass(), context.getHandler()],
      );

      if (resultRoles) {
        roles.push(...resultRoles);
      }
    } else {
      throw Error(`Unknown role merge: ${roleMerge}`);
    }

    if (roles.length === 0) {
      return true;
    }

    const roleMatchingMode = matchingMode ?? RoleMatch.ANY;

    this.logger.verbose(`Using matching mode: ${roleMatchingMode}`, { roles });

    // Extract request
    const [request] = extractRequest(context);

    // if is not an HTTP request ignore this guard
    if (!request) {
      return true;
    }
    const { accessToken } = request;

    if (!accessToken) {
      // No access token attached, auth guard should have attached the necessary token
      this.logger.warn(
        'No access token found in request, are you sure AuthGuard is first in the chain?',
      );
      return false;
    }

    // Resolve tenant config to get clientId
    const tenantConfig = await useTenantConfig(
      request,
      accessToken,
      this.singleTenant,
      this.multiTenant,
      this.keycloakOpts,
    );

    // Use native KeycloakToken for role checking — pure in-memory, no HTTP
    const token = new KeycloakToken(accessToken, tenantConfig.clientId);

    // For verbose logging, we store it instead of returning it immediately
    const granted =
      roleMatchingMode === RoleMatch.ANY
        ? roles.some((r) => token.hasRole(r))
        : roles.every((r) => token.hasRole(r));

    if (granted) {
      this.logger.verbose('Resource granted due to role(s)');
    } else {
      this.logger.verbose('Resource denied due to mismatched role(s)');
    }

    return granted;
  }
}
