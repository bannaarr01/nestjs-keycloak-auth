import { asKeycloakConfig, getPrivate } from '../helpers';
import { KeycloakAuthConfig } from '../../src/interface/keycloak-auth-options.interface';
import { KeycloakMultiTenantService } from '../../src/services/keycloak-multitenant.service';

describe('KeycloakMultiTenantService', () => {
   const baseOpts: KeycloakAuthConfig = {
      authServerUrl: 'https://kc',
      clientId: 'default-client',
      secret: 'default-secret',
      public: false,
      bearerOnly: true,
      multiTenant: {
         realmResolver: (req: unknown) =>
            (req as { realm?: string } | undefined)?.realm,
         realmClientIdResolver: (realm: string) => `${realm}-client`,
      },
   };

   it('clears cache', () => {
      const service = new KeycloakMultiTenantService(baseOpts);
      const configs = getPrivate<Map<string, unknown>>(service, 'configs');
      configs.set('a', { realm: 'a' });
      service.clear();
      expect(configs.size).toBe(0);
   });

   it('throws when options are a config path string', async () => {
      const service = new KeycloakMultiTenantService('config-path');
      await expect(service.get('a')).rejects.toThrow(
         'Keycloak configuration is a configuration path.',
      );
      await expect(service.resolveAuthServerUrl('a')).rejects.toThrow(
         'Keycloak configuration is a configuration path.',
      );
      await expect(service.resolveClientId('a')).rejects.toThrow(
         'Keycloak configuration is a configuration path.',
      );
      await expect(service.resolveSecret('a')).rejects.toThrow(
         'Keycloak configuration is a configuration path.',
      );
   });

   it('throws when multiTenant config is missing', async () => {
      const service = new KeycloakMultiTenantService({
         authServerUrl: 'x',
      } as unknown as KeycloakAuthConfig);
      await expect(service.get('a')).rejects.toThrow('Multi tenant is not defined');
      await expect(service.resolveAuthServerUrl('a')).rejects.toThrow(
         'Multi tenant is not defined',
      );
      await expect(service.resolveClientId('a')).rejects.toThrow(
         'Multi tenant is not defined',
      );
      await expect(service.resolveSecret('a')).rejects.toThrow(
         'Multi tenant is not defined',
      );
   });

   it('resolves tenant config and caches when resolveAlways is false', async () => {
      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmSecretResolver: (realm: string) => `${realm}-secret`,
            realmAuthServerUrlResolver: (realm: string) => `https://${realm}.kc`,
            resolveAlways: false,
         },
         public: true,
      });

      const first = await service.get('tenant1', { a: 1 });
      const second = await service.get('tenant1', { a: 2 });

      expect(first).toEqual({
         authServerUrl: 'https://tenant1.kc',
         realm: 'tenant1',
         clientId: 'tenant1-client',
         secret: 'tenant1-secret',
         realmUrl: 'https://tenant1.kc/realms/tenant1',
         realmAdminUrl: 'https://tenant1.kc/admin/realms/tenant1',
         isPublic: true,
         bearerOnly: true,
      });
      expect(second).toBe(first);
   });

   it('re-resolves when resolveAlways is true', async () => {
      const resolver = jest
         .fn()
         .mockReturnValueOnce('https://one.kc')
         .mockReturnValueOnce('https://two.kc');
      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            resolveAlways: true,
            realmAuthServerUrlResolver: resolver,
         },
      });

      const first = await service.get('tenant2');
      const second = await service.get('tenant2');

      expect(first.authServerUrl).toBe('https://one.kc');
      expect(second.authServerUrl).toBe('https://two.kc');
      expect(first).not.toBe(second);
   });

   it('resolves dashed public/bearer flags when building tenant config', async () => {
      const service = new KeycloakMultiTenantService({
         'auth-server-url': 'https://dash-kc',
         'client-id': 'dash-client',
         secret: 'dash-secret',
         'public-client': true,
         'bearer-only': true,
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      } as unknown as KeycloakAuthConfig);

      const result = await service.get('dash');
      expect(result.isPublic).toBe(true);
      expect(result.bearerOnly).toBe(true);
      expect(result.authServerUrl).toBe('https://dash-kc');
      expect(result.clientId).toBe('dash-client');
   });

   it('defaults public and bearerOnly to false when flags are absent', async () => {
      const service = new KeycloakMultiTenantService(asKeycloakConfig({
         authServerUrl: 'https://kc',
         clientId: 'client',
         secret: 'secret',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      }));

      const result = await service.get('tenant-default-flags');
      expect(result.isPublic).toBe(false);
      expect(result.bearerOnly).toBe(false);
   });

   it('resolveAuthServerUrl returns defaults when resolver is missing', async () => {
      const service = new KeycloakMultiTenantService(baseOpts);
      await expect(service.resolveAuthServerUrl('a')).resolves.toBe('https://kc');
   });

   it('resolveAuthServerUrl supports serverUrl and server-url fallback keys', async () => {
      const fromServerUrl = new KeycloakMultiTenantService({
         serverUrl: 'https://server-url-kc',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      } as unknown as KeycloakAuthConfig);
      await expect(fromServerUrl.resolveAuthServerUrl('a')).resolves.toBe(
         'https://server-url-kc',
      );

      const fromDashedServerUrl = new KeycloakMultiTenantService({
         'server-url': 'https://dashed-server-url-kc',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      } as unknown as KeycloakAuthConfig);
      await expect(fromDashedServerUrl.resolveAuthServerUrl('a')).resolves.toBe(
         'https://dashed-server-url-kc',
      );
   });

   it('resolveAuthServerUrl supports promise resolver and fallback when empty', async () => {
      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmAuthServerUrlResolver: jest
               .fn()
               .mockResolvedValueOnce('https://promise.kc')
               .mockResolvedValueOnce(''),
         },
      });

      await expect(service.resolveAuthServerUrl('a')).resolves.toBe(
         'https://promise.kc',
      );
      await expect(service.resolveAuthServerUrl('a')).resolves.toBe('https://kc');
   });

   it('resolveAuthServerUrl handles sync resolver returning empty string', async () => {
      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmAuthServerUrlResolver: () => '',
         },
         serverUrl: 'https://fallback-server-url',
      });

      await expect(service.resolveAuthServerUrl('a')).resolves.toBe(
         'https://kc',
      );
   });

   it('resolveAuthServerUrl falls back through auth-server-url, serverUrl, and server-url when resolver is empty', async () => {
      const fromDashedAuthServer = new KeycloakMultiTenantService({
         'auth-server-url': 'https://fallback-auth-server',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
            realmAuthServerUrlResolver: () => '',
         },
      } as unknown as KeycloakAuthConfig);
      await expect(fromDashedAuthServer.resolveAuthServerUrl('a')).resolves.toBe(
         'https://fallback-auth-server',
      );

      const fromServerUrl = new KeycloakMultiTenantService({
         serverUrl: 'https://fallback-server-url',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
            realmAuthServerUrlResolver: () => '',
         },
      } as unknown as KeycloakAuthConfig);
      await expect(fromServerUrl.resolveAuthServerUrl('a')).resolves.toBe(
         'https://fallback-server-url',
      );

      const fromDashedServerUrl = new KeycloakMultiTenantService({
         'server-url': 'https://fallback-dashed-server-url',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
            realmAuthServerUrlResolver: () => '',
         },
      } as unknown as KeycloakAuthConfig);
      await expect(fromDashedServerUrl.resolveAuthServerUrl('a')).resolves.toBe(
         'https://fallback-dashed-server-url',
      );
   });

   it('resolveClientId returns defaults and resolved values', async () => {
      const serviceNoResolver = new KeycloakMultiTenantService(asKeycloakConfig({
         ...baseOpts,
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      }));
      await expect(serviceNoResolver.resolveClientId('a')).resolves.toBe(
         'default-client',
      );

      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmClientIdResolver: jest
               .fn()
               .mockResolvedValueOnce('resolved-client')
               .mockResolvedValueOnce(''),
         },
      });

      await expect(service.resolveClientId('a')).resolves.toBe('resolved-client');
      await expect(service.resolveClientId('a')).resolves.toBe('default-client');
   });

   it('resolveClientId supports client-id fallback and sync-empty resolver result', async () => {
      const serviceNoResolver = new KeycloakMultiTenantService({
         'client-id': 'dashed-default-client',
         multiTenant: {
            realmResolver: baseOpts.multiTenant.realmResolver,
         },
      } as unknown as KeycloakAuthConfig);
      await expect(serviceNoResolver.resolveClientId('a')).resolves.toBe(
         'dashed-default-client',
      );

      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         clientId: undefined,
         'client-id': 'fallback-dashed-client',
         multiTenant: {
            ...baseOpts.multiTenant,
            realmClientIdResolver: () => '',
         },
      });
      await expect(service.resolveClientId('a')).resolves.toBe(
         'fallback-dashed-client',
      );
   });

   it('resolveSecret returns defaults and resolved values', async () => {
      const serviceNoResolver = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmSecretResolver: undefined,
         },
      });
      await expect(serviceNoResolver.resolveSecret('a')).resolves.toBe(
         'default-secret',
      );

      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmSecretResolver: jest
               .fn()
               .mockResolvedValueOnce('resolved-secret')
               .mockResolvedValueOnce(''),
         },
      });
      await expect(service.resolveSecret('a')).resolves.toBe('resolved-secret');
      await expect(service.resolveSecret('a')).resolves.toBe('default-secret');
   });

   it('resolveSecret handles sync-empty resolver result', async () => {
      const service = new KeycloakMultiTenantService({
         ...baseOpts,
         multiTenant: {
            ...baseOpts.multiTenant,
            realmSecretResolver: () => '',
         },
      });

      await expect(service.resolveSecret('a')).resolves.toBe('default-secret');
   });
});
