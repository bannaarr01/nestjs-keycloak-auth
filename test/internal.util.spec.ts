import { ExecutionContext } from '@nestjs/common';
import { extractRequest, useTenantConfig } from '../src/internal.util';
import { asKeycloakConfig, asService, makeContext, makeJwt } from './helpers';
import { ResolvedTenantConfig } from '../src/interface/tenant-config.interface';
import { KeycloakRequestLike } from '../src/interface/keycloak-request.interface';
import { KeycloakMultiTenantService } from '../src/services/keycloak-multitenant.service';

type MockMultiTenantService = {
   get: jest.MockedFunction<KeycloakMultiTenantService['get']>;
};

describe('internal.util', () => {
   const singleTenant: ResolvedTenantConfig = {
      authServerUrl: 'https://kc',
      realm: 'single',
      clientId: 'client',
      secret: 'secret',
      realmUrl: 'https://kc/realms/single',
      realmAdminUrl: 'https://kc/admin/realms/single',
      isPublic: false,
      bearerOnly: true,
   };

   it('resolves tenant using sync realmResolver', async () => {
      const multiTenant: MockMultiTenantService = {
         get: jest.fn().mockResolvedValue({ realm: 'a' }),
      };
      const opts = asKeycloakConfig({
         multiTenant: {
            realmResolver: () => 'a',
         },
      });

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         undefined,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(multiTenant.get).toHaveBeenCalledWith('a', {});
      expect(result).toEqual({ realm: 'a' });
   });

   it('resolves tenant using async realmResolver', async () => {
      const multiTenant: MockMultiTenantService = {
         get: jest.fn().mockResolvedValue({ realm: 'b' }),
      };
      const opts = asKeycloakConfig({
         multiTenant: {
            realmResolver: async () => 'b',
         },
      });

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         undefined,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(multiTenant.get).toHaveBeenCalledWith('b', {});
      expect(result).toEqual({ realm: 'b' });
   });

   it('returns single tenant when jwt is missing and opts.realm is absent', async () => {
      const multiTenant: MockMultiTenantService = { get: jest.fn() };
      const opts = asKeycloakConfig({});

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         undefined,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(result).toBe(singleTenant);
      expect(multiTenant.get).not.toHaveBeenCalled();
   });

   it('resolves tenant from issuer realm when opts.realm is absent', async () => {
      const multiTenant: MockMultiTenantService = {
         get: jest.fn().mockResolvedValue({ realm: 'issuer-realm' }),
      };
      const opts = asKeycloakConfig({});
      const jwt = makeJwt({
         iss: 'https://kc.local/realms/issuer-realm',
         exp: 9999999999,
      });

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         jwt,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(multiTenant.get).toHaveBeenCalledWith('issuer-realm', {});
      expect(result).toEqual({ realm: 'issuer-realm' });
   });

   it('falls back to single tenant when issuer parsing fails', async () => {
      const multiTenant: MockMultiTenantService = { get: jest.fn() };
      const opts = asKeycloakConfig({});
      const badJwt = 'bad-token';

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         badJwt,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(result).toBe(singleTenant);
      expect(multiTenant.get).not.toHaveBeenCalled();
   });

   it('returns single tenant when opts.realm is configured', async () => {
      const multiTenant: MockMultiTenantService = { get: jest.fn() };
      const opts = asKeycloakConfig({ realm: 'configured' });
      const jwt = makeJwt({ iss: 'https://kc.local/realms/other', exp: 9999999999 });

      const result = await useTenantConfig(
         {} as KeycloakRequestLike,
         jwt,
         singleTenant,
         asService<KeycloakMultiTenantService>(multiTenant),
         opts,
      );

      expect(result).toBe(singleTenant);
      expect(multiTenant.get).not.toHaveBeenCalled();
   });

   it('extractRequest returns request and response for http context', () => {
      const request = { id: 1 };
      const response = { id: 2 };
      const context = makeContext(request, response);

      expect(extractRequest(context)).toEqual([request, response]);
   });

   it('extractRequest returns undefined tuple for non-http context', () => {
      const context = {
         getType: () => 'rpc',
      };

      expect(extractRequest(context as unknown as ExecutionContext)).toEqual([
         undefined,
         undefined,
      ]);
   });
});
