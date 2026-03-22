import { of } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { asService, getPrivate } from '../helpers';
import { OidcDiscoveryService } from '../../src/services/oidc-discovery.service';

type MockHttpService = {
   request: jest.MockedFunction<HttpService['request']>;
};

describe('OidcDiscoveryService', () => {
   it('fetches discovery and caches endpoints', async () => {
      const httpService: MockHttpService = {
         request: jest.fn().mockReturnValue(
            of({
               data: {
                  jwks_uri: 'https://kc/jwks',
                  token_endpoint: 'https://kc/token',
                  introspection_endpoint: 'https://kc/introspect',
                  userinfo_endpoint: 'https://kc/userinfo',
               },
            }),
         ),
      };
      const service = new OidcDiscoveryService(asService<HttpService>(httpService));

      const endpoints = await service.getEndpoints('https://kc/realms/a');
      expect(endpoints).toEqual({
         jwks_uri: 'https://kc/jwks',
         token_endpoint: 'https://kc/token',
         introspection_endpoint: 'https://kc/introspect',
         userinfo_endpoint: 'https://kc/userinfo',
         end_session_endpoint: 'https://kc/realms/a/protocol/openid-connect/logout',
      });
      expect(httpService.request).toHaveBeenCalledTimes(1);

      const cached = await service.getEndpoints('https://kc/realms/a');
      expect(cached).toEqual(endpoints);
      expect(httpService.request).toHaveBeenCalledTimes(1);
   });

   it('falls back to default endpoint paths when discovery fields are missing', async () => {
      const httpService: MockHttpService = {
         request: jest.fn().mockReturnValue(of({ data: {} })),
      };
      const service = new OidcDiscoveryService(asService<HttpService>(httpService));

      const endpoints = await service.getEndpoints('https://kc/realms/fallback');
      expect(endpoints).toEqual({
         jwks_uri: 'https://kc/realms/fallback/protocol/openid-connect/certs',
         token_endpoint: 'https://kc/realms/fallback/protocol/openid-connect/token',
         introspection_endpoint:
            'https://kc/realms/fallback/protocol/openid-connect/token/introspect',
         userinfo_endpoint:
            'https://kc/realms/fallback/protocol/openid-connect/userinfo',
         end_session_endpoint:
            'https://kc/realms/fallback/protocol/openid-connect/logout',
      });
   });

   it('clears cache', async () => {
      const httpService: MockHttpService = {
         request: jest.fn().mockReturnValue(of({ data: {} })),
      };
      const service = new OidcDiscoveryService(asService<HttpService>(httpService));
      const cache = getPrivate<Map<string, unknown>>(service, 'cache');

      await service.getEndpoints('https://kc/realms/a');
      expect(cache.size).toBe(1);
      service.clearCache();
      expect(cache.size).toBe(0);
   });
});
