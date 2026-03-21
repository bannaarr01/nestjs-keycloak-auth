import { parseToken } from './util';
import { ContextType, ExecutionContext } from '@nestjs/common';
import { ResolvedTenantConfig } from './interface/tenant-config.interface';
import { KeycloakMultiTenantService } from './services/keycloak-multitenant.service';
import { KeycloakConnectConfig } from './interface/keycloak-connect-options.interface';

export interface KeycloakRequestLike {
  headers: Record<string, string | string[] | undefined>;
  cookies?: Record<string, string>;
  user?: Record<string, unknown>;
  accessToken?: string;
  scopes?: string[];
  permissions?: unknown[];
  [key: string]: unknown;
}

/**
 * Resolves the tenant configuration for the current request.
 * For multi-tenant: uses the realm resolver or extracts realm from JWT issuer.
 * For single-tenant: returns the provided default config.
 */
export const useTenantConfig = async (
  request: KeycloakRequestLike,
  jwt: string,
  singleTenantConfig: ResolvedTenantConfig,
  multiTenant: KeycloakMultiTenantService,
  opts: KeycloakConnectConfig,
): Promise<ResolvedTenantConfig> => {
  if (opts.multiTenant && opts.multiTenant.realmResolver) {
    const resolvedRealm = opts.multiTenant.realmResolver(request);
    const realm =
      resolvedRealm instanceof Promise ? await resolvedRealm : resolvedRealm;
    return await multiTenant.get(realm, request);
  } else if (!opts.realm) {
    const payload = parseToken(jwt);
    const issuerRealm = payload.iss?.split('/').pop();
    return await multiTenant.get(issuerRealm || '', request);
  }
  return singleTenantConfig;
};

export const attachCookieToHeader = (
  request: KeycloakRequestLike,
  cookieKey: string,
): KeycloakRequestLike => {
  // Attach cookie as authorization header
  if (request && request.cookies && request.cookies[cookieKey]) {
    request.headers.authorization = `Bearer ${request.cookies[cookieKey]}`;
  }

  return request;
};

type GqlContextType = 'graphql' | ContextType;

interface GqlModuleShape {
  GqlExecutionContext: {
    create(ctx: ExecutionContext): {
      getContext(): { req: KeycloakRequestLike; res: unknown };
    };
  };
}

// Cached dynamic import for @nestjs/graphql
let gqlModule: GqlModuleShape | undefined;

const loadGqlModule = async () => {
  if (!gqlModule) {
    gqlModule = (await import('@nestjs/graphql')) as unknown as GqlModuleShape;
  }
  return gqlModule;
};

export const extractRequest = (
  context: ExecutionContext,
): [KeycloakRequestLike | undefined, unknown] => {
  let request: KeycloakRequestLike | undefined;
  let response: unknown;

  // Check if request is coming from graphql or http
  if (context.getType() === 'http') {
    // http request
    const httpContext = context.switchToHttp();

    request = httpContext.getRequest() as KeycloakRequestLike;
    response = httpContext.getResponse();
  } else if (context.getType<GqlContextType>() === 'graphql') {
    if (!gqlModule) {
      throw new Error(
        '@nestjs/graphql is not loaded yet. Ensure the module is imported before handling GraphQL requests.',
      );
    }

    // graphql request
    const gqlContext =
      gqlModule.GqlExecutionContext.create(context).getContext();

    request = gqlContext.req;
    response = gqlContext.res;
  }

  return [request, response];
};

export const extractRequestAsync = async (
  context: ExecutionContext,
): Promise<[KeycloakRequestLike | undefined, unknown]> => {
  if (context.getType<GqlContextType>() === 'graphql') {
    try {
      await loadGqlModule();
    } catch {
      throw new Error('@nestjs/graphql is not installed, cannot proceed');
    }
  }
  return extractRequest(context);
};

export const extractRequestAndAttachCookie = async (
  context: ExecutionContext,
  cookieKey: string,
) => {
  const [tmpRequest, response] = await extractRequestAsync(context);
  const request = tmpRequest
    ? attachCookieToHeader(tmpRequest, cookieKey)
    : undefined;

  return [request, response] as const;
};
