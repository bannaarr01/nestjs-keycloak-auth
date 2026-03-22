import * as fs from 'fs';
import * as path from 'path';
import { Provider } from '@nestjs/common';
import { asKeycloakConfig } from './helpers';
import { TokenValidation } from '../src/constants';
import { KeycloakAuthModule } from '../src/keycloak-auth.module';
import { ResolvedTenantConfig } from '../src/interface/tenant-config.interface';
import { createKeycloakAuthOptionProvider, keycloakProvider } from '../src/keycloak-auth.providers';
import {
   KeycloakAuthConfig,
   KeycloakAuthOptions,
   NestKeycloakConfig,
} from '../src/interface/keycloak-auth-options.interface';

type KeycloakProviderFactory = (opts: KeycloakAuthOptions) => ResolvedTenantConfig;

describe('keycloak-auth.providers', () => {
   const providerFactory = (
      keycloakProvider as Provider & { useFactory: KeycloakProviderFactory }
   ).useFactory;

   afterEach(() => {
      delete process.env.TEST_AUTH_URL;
   });

   it('keycloakProvider throws when options are still a config path', () => {
      expect(() => providerFactory('path')).toThrow(
         'Keycloak configuration should have been parsed by this point.',
      );
   });

   it('keycloakProvider resolves config and warns for tokenValidation NONE', () => {
      const warnSpy = jest.spyOn(KeycloakAuthModule.logger, 'warn').mockImplementation();
      process.env.TEST_AUTH_URL = 'https://env-auth';
      const opts: KeycloakAuthConfig = {
         tokenValidation: TokenValidation.NONE,
         authServerUrl: '${env.TEST_AUTH_URL:https://fallback}',
         realm: 'master',
         clientId: 'api',
         secret: 'secret',
         public: true,
         bearerOnly: true,
      };

      const resolved = providerFactory(opts);

      expect(warnSpy).toHaveBeenCalled();
      expect(resolved).toEqual({
         authServerUrl: 'https://env-auth',
         realm: 'master',
         clientId: 'api',
         secret: 'secret',
         realmUrl: 'https://env-auth/realms/master',
         realmAdminUrl: 'https://env-auth/admin/realms/master',
         isPublic: true,
         bearerOnly: true,
      });
   });

   it('keycloakProvider uses env fallback syntax when env var is missing', () => {
      const resolved = providerFactory(asKeycloakConfig({
         authServerUrl: '${env.MISSING_AUTH:https://fallback-auth}',
         realm: 'master',
         resource: 'api-resource',
         credentials: { secret: 'cred-secret' },
         'public-client': false,
         'bearer-only': false,
      })) as ResolvedTenantConfig;

      expect(resolved.authServerUrl).toBe('https://fallback-auth');
      expect(resolved.clientId).toBe('api-resource');
      expect(resolved.secret).toBe('cred-secret');
   });

   it('keycloakProvider resolves empty string when env syntax has no fallback and env is missing', () => {
      const resolved = providerFactory(asKeycloakConfig({
         authServerUrl: '${env.MISSING_AUTH_NO_FALLBACK}',
         realm: 'master',
      })) as ResolvedTenantConfig;

      expect(resolved.authServerUrl).toBe('');
      expect(resolved.realmUrl).toBe('/realms/master');
   });

   it('keycloakProvider resolves dashed and fallback option keys', () => {
      const fromDashedServer = providerFactory({
         'server-url': 'https://dashed-server///',
         'client-id': 'dashed-client',
      } as unknown as KeycloakAuthConfig) as ResolvedTenantConfig;
      expect(fromDashedServer.authServerUrl).toBe('https://dashed-server');
      expect(fromDashedServer.realm).toBe('');
      expect(fromDashedServer.realmUrl).toBe('https://dashed-server');
      expect(fromDashedServer.realmAdminUrl).toBe('https://dashed-server');
      expect(fromDashedServer.clientId).toBe('dashed-client');
      expect(fromDashedServer.secret).toBe('');
      expect(fromDashedServer.isPublic).toBe(false);
      expect(fromDashedServer.bearerOnly).toBe(false);

      const fromServerUrl = providerFactory({
         serverUrl: 'https://camel-server',
      } as unknown as KeycloakAuthConfig) as ResolvedTenantConfig;
      expect(fromServerUrl.authServerUrl).toBe('https://camel-server');
      expect(fromServerUrl.clientId).toBe('');
   });

   it('keycloakProvider resolves public and bearer-only flags via alternate keys', () => {
      const fromPublic = providerFactory({
         authServerUrl: 'https://kc',
         public: true,
         bearerOnly: true,
      } as unknown as KeycloakAuthConfig) as ResolvedTenantConfig;
      expect(fromPublic.isPublic).toBe(true);
      expect(fromPublic.bearerOnly).toBe(true);

      const fromDashedFlags = providerFactory({
         authServerUrl: 'https://kc',
         'public-client': true,
         'bearer-only': true,
      } as unknown as KeycloakAuthConfig) as ResolvedTenantConfig;
      expect(fromDashedFlags.isPublic).toBe(true);
      expect(fromDashedFlags.bearerOnly).toBe(true);
   });

   it('keycloakProvider falls back to empty auth server url when no server key is provided', () => {
      const resolved = providerFactory({
         realm: 'master',
      } as unknown as KeycloakAuthConfig) as ResolvedTenantConfig;

      expect(resolved.authServerUrl).toBe('');
      expect(resolved.realmUrl).toBe('/realms/master');
   });

   it('createKeycloakAuthOptionProvider returns object options unchanged', () => {
      const opts = asKeycloakConfig({ authServerUrl: 'https://kc' });
      const provider = createKeycloakAuthOptionProvider(opts);

      expect(provider.useValue).toBe(opts);
   });

   it('createKeycloakAuthOptionProvider loads config from file and merges nest config', () => {
      const tempPath = path.join(process.cwd(), 'tmp-keycloak.json');
      fs.writeFileSync(
         tempPath,
         JSON.stringify({
            authServerUrl: 'https://kc',
            realm: 'r',
            clientId: 'c',
            secret: 's',
         }),
      );
      const provider = createKeycloakAuthOptionProvider('./tmp-keycloak.json', {
         policyEnforcement:
            'permissive' as NestKeycloakConfig['policyEnforcement'],
      });
      fs.unlinkSync(tempPath);

      expect(provider.useValue).toMatchObject({
         authServerUrl: 'https://kc',
         realm: 'r',
         clientId: 'c',
         secret: 's',
         policyEnforcement: 'permissive',
      });
   });

   it('createKeycloakAuthOptionProvider loads config from path relative to source directory', () => {
      const relativeFile = path.join(process.cwd(), 'src', 'tmp-relative-keycloak.json');
      fs.writeFileSync(
         relativeFile,
         JSON.stringify({
            authServerUrl: 'https://rel-kc',
            realm: 'rel',
            clientId: 'rel-client',
            secret: 'rel-secret',
         }),
      );

      const provider = createKeycloakAuthOptionProvider('./tmp-relative-keycloak.json');
      fs.unlinkSync(relativeFile);

      expect(provider.useValue).toMatchObject({
         authServerUrl: 'https://rel-kc',
         realm: 'rel',
         clientId: 'rel-client',
      });
   });

   it('throws when config file path cannot be found', () => {
      expect(() =>
         createKeycloakAuthOptionProvider('./missing-keycloak.json'),
      ).toThrow('Cannot find files, looked in');
   });
});
