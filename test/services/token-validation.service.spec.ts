import * as crypto from 'crypto';
import { JwksCacheService } from '../../src/services/jwks-cache.service';
import { KeycloakHttpService } from '../../src/services/keycloak-http.service';
import { TokenValidationService } from '../../src/services/token-validation.service';
import { asKeycloakConfig, asService, callPrivate, getPrivate, makeJwt, TestKeycloakConfig } from '../helpers';

const cryptoModule = jest.requireActual<typeof import('crypto')>('crypto');

type MockKeycloakHttpService = {
   introspectToken: jest.MockedFunction<KeycloakHttpService['introspectToken']>;
};

type MockJwksCacheService = {
   getKey: jest.MockedFunction<JwksCacheService['getKey']>;
};

describe('TokenValidationService', () => {
   const realmUrl = 'https://kc/realms/a';

   afterEach(() => {
      jest.restoreAllMocks();
   });

   const buildService = (opts: TestKeycloakConfig = {}) => {
      const keycloakHttp: MockKeycloakHttpService = {
         introspectToken: jest.fn(),
      };
      const jwksCache: MockJwksCacheService = {
         getKey: jest.fn(),
      };
      const service = new TokenValidationService(
         asKeycloakConfig(opts),
         asService<KeycloakHttpService>(keycloakHttp),
         asService<JwksCacheService>(jwksCache),
      );
      return { service, keycloakHttp, jwksCache };
   };

   it('supports notBefore global and per-realm state', () => {
      const { service } = buildService();

      expect(service.notBefore).toBe(0);
      service.notBefore = 5;
      expect(service.notBefore).toBe(5);
      expect(service.getNotBefore()).toBe(5);
      expect(service.getNotBefore('realm-a')).toBe(5);

      service.setNotBefore(10, 'realm-a');
      expect(service.getNotBefore('realm-a')).toBe(10);
      expect(service.getNotBefore('realm-b')).toBe(5);

      service.setNotBefore(20);
      expect(service.getNotBefore()).toBe(20);
   });

   it('validates token online and handles errors', async () => {
      const { service, keycloakHttp } = buildService();
      keycloakHttp.introspectToken.mockResolvedValueOnce({ active: true });
      keycloakHttp.introspectToken.mockResolvedValueOnce({ active: false });
      keycloakHttp.introspectToken.mockRejectedValueOnce(new Error('boom'));

      await expect(
         service.validateOnline('jwt', realmUrl, 'client', 'secret'),
      ).resolves.toBe(true);
      await expect(
         service.validateOnline('jwt', realmUrl, 'client', 'secret'),
      ).resolves.toBe(false);
      await expect(
         service.validateOnline('jwt', realmUrl, 'client', 'secret'),
      ).resolves.toBe(false);
   });

   it('formats static realm public key in constructor', async () => {
      const { service } = buildService({ realmPublicKey: 'A'.repeat(65) });
      const publicKey = getPrivate<string | undefined>(service, 'publicKey');
      expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
      expect(publicKey).toContain('-----END PUBLIC KEY-----');
   });

   it('fails offline validation for malformed token', async () => {
      const { service } = buildService();
      await expect(service.validateOffline('bad-token', realmUrl, 'client')).resolves.toBe(false);
   });

   it('fails offline validation for expired token', async () => {
      jest.spyOn(Date, 'now').mockReturnValue(2000);
      const { service } = buildService();
      const jwt = makeJwt({ exp: 1, typ: 'Bearer', iat: 1, iss: realmUrl });
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('fails offline validation for wrong token type', async () => {
      const { service } = buildService();
      const jwt = makeJwt({ exp: 9999999999, typ: 'Refresh', iat: 1, iss: realmUrl });
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('fails offline validation for stale token by notBefore', async () => {
      const { service } = buildService();
      service.setNotBefore(100, realmUrl);
      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 1, iss: realmUrl });
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('fails offline validation for wrong issuer', async () => {
      const { service } = buildService();
      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 100, iss: 'wrong' });
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('fails offline validation for audience mismatch when enabled', async () => {
      const { service } = buildService({ verifyTokenAudience: true });
      const jwt = makeJwt({
         exp: 9999999999,
         typ: 'Bearer',
         iat: 100,
         iss: realmUrl,
         aud: 'other',
      });
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('validates with static public key and handles invalid signature', async () => {
      const keyObject = {} as crypto.KeyObject;
      jest.spyOn(cryptoModule, 'createPublicKey').mockReturnValue(keyObject);
      jest
         .spyOn(cryptoModule, 'verify')
         .mockImplementationOnce(() => false)
         .mockImplementationOnce(() => true);

      const { service } = buildService({ 'realm-public-key': 'A'.repeat(10) });
      const jwt = makeJwt({
         exp: 9999999999,
         typ: 'Bearer',
         iat: 100,
         iss: realmUrl,
         aud: 'client',
      });

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(true);
   });

   it('fails when kid is missing in jwks mode', async () => {
      const { service } = buildService();
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'RS256', typ: 'JWT' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('validates via jwks path with ES algorithms', async () => {
      const verifySpy = jest
         .spyOn(cryptoModule, 'verify')
         .mockImplementationOnce(() => false)
         .mockImplementationOnce(() => true);
      const { service, jwksCache } = buildService();
      jwksCache.getKey.mockResolvedValue({} as crypto.KeyObject);
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'ES256', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(true);
      expect(verifySpy).toHaveBeenCalledWith(
         'SHA256',
         expect.any(Buffer),
         expect.any(Object),
         expect.any(Buffer),
      );
   });

   it('returns false on offline validation exceptions', async () => {
      const { service, jwksCache } = buildService();
      jwksCache.getKey.mockRejectedValue(new Error('no key'));
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'PS512', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
   });

   it('uses RS256 as fallback when JWT alg header is missing', async () => {
      const verifySpy = jest.spyOn(cryptoModule, 'verify').mockImplementation(() => true);
      const { service, jwksCache } = buildService();
      jwksCache.getKey.mockResolvedValue({} as crypto.KeyObject);
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(true);
      expect(verifySpy).toHaveBeenCalledWith(
         'SHA256',
         expect.any(Buffer),
         expect.any(Object),
         expect.any(Buffer),
      );
   });

   it('supports PS algorithms with static public key and PSS verification', async () => {
      const keyObject = {} as crypto.KeyObject;
      const createPublicKeySpy = jest
         .spyOn(cryptoModule, 'createPublicKey')
         .mockReturnValue(keyObject);
      const verifySpy = jest.spyOn(cryptoModule, 'verify').mockImplementation(() => true);

      const { service } = buildService({ realmPublicKey: 'A'.repeat(10) });
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'PS512', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(true);
      expect(createPublicKeySpy).toHaveBeenCalled();
      expect(verifySpy).toHaveBeenCalledWith(
         'SHA512',
         expect.any(Buffer),
         expect.objectContaining({
            key: keyObject,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
         }),
         expect.any(Buffer),
      );
   });

   it('supports PS algorithms with JWKS key objects without createPublicKey', async () => {
      const keyObject = {} as crypto.KeyObject;
      const verifySpy = jest.spyOn(cryptoModule, 'verify').mockImplementation(() => true);
      const createPublicKeySpy = jest.spyOn(cryptoModule, 'createPublicKey');
      const { service, jwksCache } = buildService();
      jwksCache.getKey.mockResolvedValue(keyObject);
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'PS256', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(true);
      expect(verifySpy).toHaveBeenCalled();
      expect(createPublicKeySpy).not.toHaveBeenCalled();
   });

   it('falls back to SHA256 when JWT algorithm is unknown', async () => {
      const { service, jwksCache } = buildService();
      jwksCache.getKey.mockResolvedValue({} as crypto.KeyObject);
      const verifySpy = jest.spyOn(cryptoModule, 'verify');
      const jwt = makeJwt(
         {
            exp: 9999999999,
            typ: 'Bearer',
            iat: 100,
            iss: realmUrl,
            aud: ['client'],
         },
         { alg: 'UNKNOWN', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.validateOffline(jwt, realmUrl, 'client')).resolves.toBe(false);
      expect(verifySpy).not.toHaveBeenCalled();
   });

   it('verifySignature falls back to SHA256 for unknown algorithm values', () => {
      const { service } = buildService();
      const verifySpy = jest.spyOn(cryptoModule, 'verify').mockImplementation(() => true);
      const keyObject = {} as crypto.KeyObject;

      const result = callPrivate<[string, Buffer, crypto.KeyObject, string], boolean>(
         service,
         'verifySignature',
         'signed',
         Buffer.from('sig'),
         keyObject,
         'UNKNOWN',
      );

      expect(result).toBe(true);
      expect(verifySpy).toHaveBeenCalledWith(
         'SHA256',
         expect.any(Buffer),
         keyObject,
         expect.any(Buffer),
      );
   });
});
