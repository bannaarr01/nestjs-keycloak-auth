import * as crypto from 'crypto';
import { CachedJwks } from '../../src/interface/jwks.interface';
import { asKeycloakConfig, asService, getPrivate } from '../helpers';
import { JwksCacheService } from '../../src/services/jwks-cache.service';
import { KeycloakHttpService } from '../../src/services/keycloak-http.service';

type MockKeycloakHttpService = {
   fetchJwks: jest.MockedFunction<KeycloakHttpService['fetchJwks']>;
};

jest.mock('crypto', () => {
   const actual = jest.requireActual('crypto');
   return {
      ...actual,
      createPublicKey: jest.fn(),
   };
});

describe('JwksCacheService', () => {
   afterEach(() => {
      jest.restoreAllMocks();
      (crypto.createPublicKey as unknown as jest.Mock).mockReset();
   });

   it('fetches key and caches jwks', async () => {
      const keyObject = {} as crypto.KeyObject;
      (crypto.createPublicKey as unknown as jest.Mock).mockReturnValue(keyObject);
      const keycloakHttp: MockKeycloakHttpService = {
         fetchJwks: jest.fn().mockResolvedValue({
            keys: [{ kid: 'k1', kty: 'RSA', n: 'n', e: 'AQAB' }],
         }),
      };
      const service = new JwksCacheService(
         asKeycloakConfig({ secret: 's' }),
         asService<KeycloakHttpService>(keycloakHttp),
      );
      const cache = getPrivate<Map<string, CachedJwks>>(service, 'cache');

      const result = await service.getKey('realm-url', 'k1');

      expect(result).toBe(keyObject);
      expect(keycloakHttp.fetchJwks).toHaveBeenCalledTimes(1);
      expect(crypto.createPublicKey).toHaveBeenCalled();
      expect(cache.get('realm-url')?.keys.size).toBe(1);
   });

   it('refetches when kid is missing and min interval elapsed', async () => {
      const keyObject = {} as crypto.KeyObject;
      (crypto.createPublicKey as unknown as jest.Mock).mockReturnValue(keyObject);
      const keycloakHttp: MockKeycloakHttpService = {
         fetchJwks: jest
            .fn()
            .mockResolvedValueOnce({
               keys: [{ kid: 'old', kty: 'RSA', n: 'n', e: 'AQAB' }],
            })
            .mockResolvedValueOnce({
               keys: [{ kid: 'new', kty: 'RSA', n: 'n', e: 'AQAB' }],
            }),
      };
      const service = new JwksCacheService(
         asKeycloakConfig({ secret: 's' }),
         asService<KeycloakHttpService>(keycloakHttp),
      );
      service.setMinTimeBetweenRequests(10);

      const now = jest
         .spyOn(Date, 'now')
         .mockReturnValueOnce(0)
         .mockReturnValueOnce(1000)
         .mockReturnValue(1000);

      const result = await service.getKey('realm', 'new');
      expect(result).toBe(keyObject);
      expect(keycloakHttp.fetchJwks).toHaveBeenCalledTimes(2);
      now.mockRestore();
   });

   it('throws when kid is missing and refetch is not allowed', async () => {
      (crypto.createPublicKey as unknown as jest.Mock).mockReturnValue(
         {} as unknown as crypto.KeyObject,
      );
      const keycloakHttp: MockKeycloakHttpService = {
         fetchJwks: jest.fn().mockResolvedValue({
            keys: [{ kid: 'old', kty: 'RSA', n: 'n', e: 'AQAB' }],
         }),
      };
      const service = new JwksCacheService(
         asKeycloakConfig({ secret: 's' }),
         asService<KeycloakHttpService>(keycloakHttp),
      );
      service.setMinTimeBetweenRequests(100000);
      jest.spyOn(Date, 'now').mockReturnValue(1000);

      await expect(service.getKey('realm', 'missing')).rejects.toThrow(
         "Key 'missing' not found in JWKS for realm: realm",
      );
      expect(keycloakHttp.fetchJwks).toHaveBeenCalledTimes(1);
   });

   it('uses configured minTimeBetweenJwksRequests and clearCache', async () => {
      const keycloakHttp: MockKeycloakHttpService = {
         fetchJwks: jest.fn().mockResolvedValue({
            keys: [
               { kid: 'k1', kty: 'RSA', n: 'n', e: 'AQAB' },
               { kty: 'RSA', n: 'n2', e: 'AQAB' }, // no kid should be ignored
            ],
         }),
      };
      (crypto.createPublicKey as unknown as jest.Mock).mockReturnValue(
         {} as unknown as crypto.KeyObject,
      );
      const service = new JwksCacheService(
         asKeycloakConfig({ minTimeBetweenJwksRequests: 7 }),
         asService<KeycloakHttpService>(keycloakHttp),
      );
      const minTimeBetweenRequestsMs = getPrivate<number>(
         service,
         'minTimeBetweenRequestsMs',
      );
      const cache = getPrivate<Map<string, CachedJwks>>(service, 'cache');

      expect(minTimeBetweenRequestsMs).toBe(7000);
      await service.getKey('realm', 'k1');
      expect(cache.size).toBe(1);
      service.clearCache();
      expect(cache.size).toBe(0);
   });

   it('supports dashed min-time-between-jwks-requests config key', () => {
      const service = new JwksCacheService(
         asKeycloakConfig({ 'min-time-between-jwks-requests': 3 }),
         asService<KeycloakHttpService>({ fetchJwks: jest.fn() }),
      );
      expect(getPrivate<number>(service, 'minTimeBetweenRequestsMs')).toBe(3000);
   });

   it('reuses cached jwks on subsequent lookups without refetch', async () => {
      (crypto.createPublicKey as unknown as jest.Mock).mockReturnValue(
         {} as unknown as crypto.KeyObject,
      );
      const keycloakHttp: MockKeycloakHttpService = {
         fetchJwks: jest.fn().mockResolvedValue({
            keys: [{ kid: 'k1', kty: 'RSA', n: 'n', e: 'AQAB' }],
         }),
      };
      const service = new JwksCacheService(
         asKeycloakConfig({ secret: 's' }),
         asService<KeycloakHttpService>(keycloakHttp),
      );

      await service.getKey('realm', 'k1');
      await service.getKey('realm', 'k1');

      expect(keycloakHttp.fetchJwks).toHaveBeenCalledTimes(1);
   });
});
