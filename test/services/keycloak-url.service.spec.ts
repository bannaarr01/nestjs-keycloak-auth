import { KeycloakUrlService } from '../../src/services/keycloak-url.service';
import { KeycloakAuthConfig } from '../../src/interface/keycloak-auth-options.interface';

describe('KeycloakUrlService', () => {
   it('builds realm admin url and trims trailing slashes', () => {
      const service = new KeycloakUrlService({
         authServerUrl: 'https://kc.local///',
         realm: 'master',
      } as unknown as KeycloakAuthConfig);

      expect(service.realmAdminUrl()).toBe('https://kc.local/admin/realms/master');
   });

   it('supports dashed server option names', () => {
      const service = new KeycloakUrlService({
         'auth-server-url': 'https://kc.local',
         realm: 'tenant',
      } as unknown as KeycloakAuthConfig);

      expect(service.realmAdminUrl()).toBe('https://kc.local/admin/realms/tenant');
   });

   it('supports serverUrl and server-url fallbacks and empty realm fallback', () => {
      const fromServerUrl = new KeycloakUrlService({
         serverUrl: 'https://kc.server-url',
         realm: 'tenant2',
      } as unknown as KeycloakAuthConfig);
      expect(fromServerUrl.realmAdminUrl()).toBe(
         'https://kc.server-url/admin/realms/tenant2',
      );

      const fromDashedServerUrl = new KeycloakUrlService({
         'server-url': 'https://kc.dashed-server-url',
      } as unknown as KeycloakAuthConfig);
      expect(fromDashedServerUrl.realmAdminUrl()).toBe(
         'https://kc.dashed-server-url/admin/realms/',
      );
   });

   it('falls back to empty auth server url when no server keys are provided', () => {
      const service = new KeycloakUrlService({} as unknown as KeycloakAuthConfig);
      expect(service.realmAdminUrl()).toBe('/admin/realms/');
   });
});
