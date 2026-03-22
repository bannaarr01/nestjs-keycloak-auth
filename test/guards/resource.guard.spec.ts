import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { PolicyEnforcementMode } from '../../src/constants';
import { ResourceGuard } from '../../src/guards/resource.guard';
import { KeycloakHttpService } from '../../src/services/keycloak-http.service';
import { KeycloakPermission } from '../../src/interface/keycloak-grant.interface';
import { ResolvedTenantConfig } from '../../src/interface/tenant-config.interface';
import { KeycloakEnforcerOptions } from '../../src/interface/enforcer-options.interface';
import { KeycloakMultiTenantService } from '../../src/services/keycloak-multitenant.service';
import {
   asKeycloakConfig,
   asService,
   callPrivate,
   getPrivate,
   makeContext,
   makeJwt,
   TestKeycloakConfig,
} from '../helpers';

type RequestLike = {
   headers: Record<string, string | string[] | undefined>;
   user?: { preferred_username?: string };
   accessToken?: string;
   url?: string;
   originalUrl?: string;
   scopes?: string[];
   permissions?: KeycloakPermission[];
};

type MockKeycloakHttpService = {
   checkPermission: jest.Mock;
};

type MetadataOptions = {
   resource?: string;
   scopes?: string[];
   conditional?: (req: RequestLike, token: unknown) => string[];
   isPublic?: boolean;
   enforcerOptions?: KeycloakEnforcerOptions;
};

describe('ResourceGuard', () => {
   const singleTenant: ResolvedTenantConfig = {
      authServerUrl: 'https://kc',
      realm: 'a',
      realmUrl: 'https://kc/realms/a',
      realmAdminUrl: 'https://kc/admin/realms/a',
      clientId: 'api',
      secret: 'secret',
      isPublic: false,
      bearerOnly: true,
   };

   const buildGuard = (opts: TestKeycloakConfig = {}) => {
      const keycloakHttp: MockKeycloakHttpService = {
         checkPermission: jest.fn(),
      };
      const guard = new ResourceGuard(
         singleTenant,
         asKeycloakConfig(opts),
         asService<KeycloakMultiTenantService>({}),
         asService<KeycloakHttpService>(keycloakHttp),
      );
      return { guard, keycloakHttp };
   };

   const mockMetadata = (guard: ResourceGuard, data: MetadataOptions = {}) => {
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest.spyOn(reflector, 'get').mockImplementation((key: string) => {
         if (key === 'resource') {
            return data.resource;
         }
         if (key === 'scopes') {
            return data.scopes;
         }
         if (key === 'conditional-scopes') {
            return data.conditional;
         }
         return undefined;
      });
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'public') {
               return data.isPublic;
            }
            if (key === 'enforcer-options') {
               return data.enforcerOptions;
            }
            return undefined;
         });
   };

   it('allows non-http context', async () => {
      const { guard } = buildGuard();
      const context = {
         getType: () => 'rpc',
         getClass: () => class A {},
         getHandler: () => () => undefined,
      };
      await expect(
         guard.canActivate(context as unknown as ExecutionContext),
      ).resolves.toBe(true);
   });

   it('allows public route with no user', async () => {
      const { guard } = buildGuard({ realm: 'master' });
      mockMetadata(guard, { isPublic: true });
      const request: RequestLike = { headers: {} };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
   });

   it('enforces policy when resource metadata is missing', async () => {
      const { guard: permissive } = buildGuard({
         realm: 'master',
         policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
      });
      mockMetadata(permissive, { isPublic: false, resource: undefined, scopes: ['view'] });
      const req1: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: 'x',
      };
      await expect(permissive.canActivate(makeContext(req1))).resolves.toBe(true);

      const { guard: enforcing } = buildGuard({
         realm: 'master',
         policyEnforcement: PolicyEnforcementMode.ENFORCING,
      });
      mockMetadata(enforcing, { isPublic: false, resource: undefined, scopes: ['view'] });
      const req2: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: 'x',
      };
      await expect(enforcing.canActivate(makeContext(req2))).resolves.toBe(false);
   });

   it('enforces policy when scopes are missing', async () => {
      const { guard: permissive } = buildGuard({
         realm: 'master',
         policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
      });
      mockMetadata(permissive, {
         resource: 'orders',
         scopes: [],
      });
      const req1: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: 'x',
      };
      await expect(permissive.canActivate(makeContext(req1))).resolves.toBe(true);
      expect(req1.scopes).toEqual([]);

      const { guard: enforcing } = buildGuard({
         realm: 'master',
         policyEnforcement: PolicyEnforcementMode.ENFORCING,
      });
      mockMetadata(enforcing, {
         resource: 'orders',
         scopes: [],
      });
      const req2: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: 'x',
      };
      await expect(enforcing.canActivate(makeContext(req2))).resolves.toBe(false);
   });

   it('grants by local token permission check', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
      });
      const localToken = makeJwt({
         exp: 9999999999,
         authorization: {
            permissions: [{ rsid: 'orders', scopes: ['view'] }],
         },
      });
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: localToken,
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(keycloakHttp.checkPermission).not.toHaveBeenCalled();
   });

   it('uses permissions response mode and attaches permissions on allow', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
      });
      keycloakHttp.checkPermission.mockResolvedValueOnce([
         { rsid: 'orders', scopes: ['view'] },
      ]);
      const token = makeJwt({ exp: 9999999999 });
      const request: RequestLike = {
         headers: { 'user-agent': 'jest' },
         url: '/orders',
         user: { preferred_username: 'john' },
         accessToken: token,
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(request.permissions).toEqual([{ rsid: 'orders', scopes: ['view'] }]);
      const options = keycloakHttp.checkPermission.mock.calls[0][5] as {
         response_mode: string;
         claims: Record<string, string[]>;
      };
      expect(options.response_mode).toBe('permissions');
      expect(options.claims['http.uri']).toEqual(['/orders']);
      expect(options.claims['user.agent']).toEqual(['jest']);
   });

   it('handles requests without accessToken by skipping local permission check', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
      });
      keycloakHttp.checkPermission.mockRejectedValueOnce(new Error('boom'));
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);
      expect(keycloakHttp.checkPermission).toHaveBeenCalled();
   });

   it('denies permissions mode when server returns invalid permissions or throws', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
      });
      keycloakHttp.checkPermission.mockResolvedValueOnce([
         { rsid: 'orders', scopes: ['edit'] },
      ]);
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: makeJwt({ exp: 9999999999 }),
      };
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);

      keycloakHttp.checkPermission.mockRejectedValueOnce(new Error('boom'));
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);
   });

   it('supports token response mode', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         enforcerOptions: { response_mode: 'token' },
      });
      keycloakHttp.checkPermission.mockResolvedValueOnce({
         access_token: makeJwt({
            exp: 9999999999,
            authorization: { permissions: [{ rsid: 'orders', scopes: ['view'] }] },
         }),
      });
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);

      keycloakHttp.checkPermission.mockRejectedValueOnce(new Error('boom'));
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);
   });

   it('denies token response mode when granted token lacks required permission', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         enforcerOptions: { response_mode: 'token' },
      });
      keycloakHttp.checkPermission.mockResolvedValueOnce({
         access_token: makeJwt({
            exp: 9999999999,
            authorization: { permissions: [{ rsid: 'orders', scopes: ['edit'] }] },
         }),
      });
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);
   });

   it('supports decision response mode', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         enforcerOptions: { response_mode: 'decision', claims: () => ({ c: 1 }) },
      });
      const request: RequestLike = {
         headers: {},
         user: { preferred_username: 'john' },
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      keycloakHttp.checkPermission.mockResolvedValueOnce(true);
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(
         (keycloakHttp.checkPermission.mock.calls[0][5] as { claims?: Record<string, unknown> })
            .claims,
      ).toEqual({ c: 1 });

      keycloakHttp.checkPermission.mockResolvedValueOnce(false);
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(false);
   });

   it('passes undefined claims to server when custom claims resolver returns undefined', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         enforcerOptions: { claims: () => undefined },
      });
      const request: RequestLike = {
         headers: {},
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      keycloakHttp.checkPermission.mockResolvedValueOnce([
         { rsid: 'orders', scopes: ['view'] },
      ]);
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(
         (keycloakHttp.checkPermission.mock.calls[0][5] as { claims?: unknown }).claims,
      ).toBeUndefined();
   });

   it('supports anonymous user fallback label in decision mode logging path', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         enforcerOptions: { response_mode: 'decision', claims: () => undefined },
      });
      const request: RequestLike = {
         headers: {},
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      keycloakHttp.checkPermission.mockResolvedValueOnce(true);
      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(
         (keycloakHttp.checkPermission.mock.calls[0][5] as { claims?: unknown }).claims,
      ).toBeUndefined();
   });

   it('evaluates conditional scopes and resolves fallback originalUrl claim', async () => {
      const { guard, keycloakHttp } = buildGuard({ realm: 'master' });
      mockMetadata(guard, {
         resource: 'orders',
         scopes: ['view'],
         conditional: () => ['extra'],
      });
      keycloakHttp.checkPermission.mockResolvedValueOnce([
         { rsid: 'orders', scopes: ['view', 'extra'] },
      ]);
      const request: RequestLike = {
         headers: {},
         originalUrl: '/orig',
         user: { preferred_username: 'john' },
         accessToken: makeJwt({ exp: 9999999999 }),
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(request.scopes).toEqual(['view', 'extra']);
      const claims = (
         keycloakHttp.checkPermission.mock.calls[0][5] as {
            claims: Record<string, string[]>;
         }
      ).claims;
      expect(claims['http.uri']).toEqual(['/orig']);
   });

   it('validatePermissionsLocally covers edge cases', () => {
      const { guard } = buildGuard({ realm: 'master' });
      const validate = (
         serverPermissions: KeycloakPermission[],
         resource: string,
         scopes: string[],
      ) =>
         callPrivate<
            [KeycloakPermission[], string, string[]],
            boolean
         >(
            guard,
            'validatePermissionsLocally',
            serverPermissions,
            resource,
            scopes,
         );

      expect(validate([], 'orders', ['view'])).toBe(false);
      expect(validate([{ rsid: 'orders' }], 'orders', ['view'])).toBe(false);
      expect(validate([{ rsid: 'orders', scopes: ['other'] }], 'orders', ['view'])).toBe(
         false,
      );
      expect(validate([{ rsname: 'orders', scopes: ['view'] }], 'orders', ['view'])).toBe(
         true,
      );
      expect(validate([{ rsid: 'other', scopes: ['view'] }], 'orders', ['view'])).toBe(
         false,
      );
      expect(validate([{ rsid: 'orders' }], 'orders', [''])).toBe(true);
   });

   it('resolveClaims uses custom claims or defaults', () => {
      const { guard } = buildGuard({ realm: 'master' });
      const resolveClaims = (
         request: Record<string, unknown>,
         enforcerOptions?: KeycloakEnforcerOptions,
      ) =>
         callPrivate<
            [Record<string, unknown>, KeycloakEnforcerOptions | undefined],
            Record<string, unknown> | undefined
         >(guard, 'resolveClaims', request, enforcerOptions);
      const req: Record<string, unknown> = {
         headers: { 'user-agent': ['ua1', 'ua2'] },
         url: '/u',
      };

      expect(resolveClaims(req, { claims: () => ({ x: 1 }) })).toEqual({ x: 1 });
      expect(resolveClaims(req, undefined)).toEqual({
         'http.uri': ['/u'],
         'user.agent': ['ua1'],
      });
      expect(resolveClaims({}, undefined)).toEqual({
         'http.uri': [''],
         'user.agent': [''],
      });
   });
});
