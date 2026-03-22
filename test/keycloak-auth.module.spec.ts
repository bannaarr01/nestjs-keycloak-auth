import { Provider } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { KEYCLOAK_AUTH_OPTIONS } from '../src/constants';
import { KeycloakAuthModule } from '../src/keycloak-auth.module';
import { KeycloakAuthConfig } from '../src/interface/keycloak-auth-options.interface';
import { KeycloakAuthModuleAsyncOptions } from '../src/interface/keycloak-auth-module-async-options.interface';

type AsyncProviderLike = Provider & {
   provide: unknown;
   useFactory?: (...args: unknown[]) => unknown;
   inject?: unknown[];
   useClass?: unknown;
};

describe('KeycloakAuthModule', () => {
   it('register creates dynamic module with providers/controllers/imports', () => {
      const dynamic = KeycloakAuthModule.register({
         authServerUrl: 'https://kc',
         realm: 'master',
         clientId: 'api',
         secret: 'secret',
      } as KeycloakAuthConfig);

      expect(dynamic.module).toBe(KeycloakAuthModule);
      expect(dynamic.imports).toContain(HttpModule);
      expect(dynamic.controllers?.length).toBe(1);
      expect(dynamic.providers?.length).toBeGreaterThan(0);
      expect(dynamic.exports?.length).toBeGreaterThan(0);
   });

   it('registerAsync supports useFactory/useExisting', async () => {
      const dynamic = KeycloakAuthModule.registerAsync({
         useFactory: () =>
            ({
               authServerUrl: 'https://kc',
               realm: 'master',
               clientId: 'api',
               secret: 'secret',
            }) as KeycloakAuthConfig,
         inject: ['X'],
      });

      expect(dynamic.module).toBe(KeycloakAuthModule);
      expect(dynamic.imports).toContain(HttpModule);
      expect(dynamic.controllers?.length).toBe(1);

      const optionsProvider = (dynamic.providers as AsyncProviderLike[]).find(
         (p) => p.provide === KEYCLOAK_AUTH_OPTIONS,
      ) as AsyncProviderLike;
      expect(optionsProvider.inject).toEqual(['X']);
      expect(await optionsProvider.useFactory()).toEqual({
         authServerUrl: 'https://kc',
         realm: 'master',
         clientId: 'api',
         secret: 'secret',
      });
   });

   it('registerAsync sets empty inject list when useFactory inject is omitted', () => {
      const dynamic = KeycloakAuthModule.registerAsync({
         useFactory: () => ({ authServerUrl: 'https://kc' } as KeycloakAuthConfig),
      });

      const optionsProvider = (dynamic.providers as AsyncProviderLike[]).find(
         (p) => p.provide === KEYCLOAK_AUTH_OPTIONS,
      ) as AsyncProviderLike;
      expect(optionsProvider.inject).toEqual([]);
   });

   it('registerAsync supports useClass and createAsync options provider fallback', async () => {
      class FactoryClass {
         createKeycloakAuthOptions(): KeycloakAuthConfig {
            return {
               authServerUrl: 'https://kc',
               realm: 'master',
               clientId: 'api',
               secret: 'secret',
            };
         }
      }

      const dynamic = KeycloakAuthModule.registerAsync({
         useClass: FactoryClass,
      } as KeycloakAuthModuleAsyncOptions);
      const providers = dynamic.providers as AsyncProviderLike[];
      const classProvider = providers.find((p) => p.provide === FactoryClass);
      expect(classProvider.useClass).toBe(FactoryClass);

      const optionsProvider = providers.find(
         (p) => p.provide === KEYCLOAK_AUTH_OPTIONS,
      );
      expect(optionsProvider.inject).toEqual([FactoryClass]);
      await expect(
         optionsProvider.useFactory(new FactoryClass()),
      ).resolves.toEqual({
         authServerUrl: 'https://kc',
         realm: 'master',
         clientId: 'api',
         secret: 'secret',
      });
   });
});
