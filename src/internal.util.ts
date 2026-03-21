import { parseToken } from './util';
import { ExecutionContext } from '@nestjs/common';
import { ResolvedTenantConfig } from './interface/tenant-config.interface';
import { KeycloakRequestLike } from './interface/keycloak-request.interface';
import { KeycloakAuthConfig } from './interface/keycloak-auth-options.interface';
import { KeycloakMultiTenantService } from './services/keycloak-multitenant.service';

export { KeycloakRequestLike };

/**
 * Resolves the tenant configuration for the current request.
 * For multi-tenant: uses the realm resolver or extracts realm from JWT issuer.
 * For single-tenant: returns the provided default config.
 */
export const useTenantConfig = async (
   request: KeycloakRequestLike,
   jwt: string | undefined,
   singleTenantConfig: ResolvedTenantConfig,
   multiTenant: KeycloakMultiTenantService,
   opts: KeycloakAuthConfig,
): Promise<ResolvedTenantConfig> => {
   if (opts.multiTenant && opts.multiTenant.realmResolver) {
      const resolvedRealm = opts.multiTenant.realmResolver(request);
      const realm =
      resolvedRealm instanceof Promise ? await resolvedRealm : resolvedRealm;
      return await multiTenant.get(realm, request);
   } else if (!opts.realm) {
      if (!jwt) {
         return singleTenantConfig;
      }

      try {
         const payload = parseToken(jwt);
         const issuerRealm = payload.iss?.split('/').pop();
         if (issuerRealm) {
            return await multiTenant.get(issuerRealm, request);
         }
      } catch {
      // Fall back to the default config when issuer parsing fails.
         return singleTenantConfig;
      }
   }
   return singleTenantConfig;
};

export const extractRequest = (
   context: ExecutionContext,
): [KeycloakRequestLike | undefined, unknown] => {
   if (context.getType() === 'http') {
      const httpContext = context.switchToHttp();
      const request = httpContext.getRequest() as KeycloakRequestLike;
      const response = httpContext.getResponse();
      return [request, response];
   }

   return [undefined, undefined];
};
