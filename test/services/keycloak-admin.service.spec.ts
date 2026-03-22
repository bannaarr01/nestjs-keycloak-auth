import * as crypto from 'crypto';
import { KeycloakToken } from '../../src/token/keycloak-token';
import { ServerRequest } from '../../src/interface/server.interface';
import { JwksCacheService } from '../../src/services/jwks-cache.service';
import { KeycloakAdminError, KeycloakConfigError } from '../../src/errors';
import { KeycloakAdminService } from '../../src/services/keycloak-admin.service';
import { ResolvedTenantConfig } from '../../src/interface/tenant-config.interface';
import { TokenValidationService } from '../../src/services/token-validation.service';
import { BackchannelLogoutService } from '../../src/services/backchannel-logout.service';
import { KeycloakMultiTenantService } from '../../src/services/keycloak-multitenant.service';
import { asKeycloakConfig, asService, callPrivate, makeJwt, TestKeycloakConfig } from '../helpers';

jest.mock('crypto', () => {
   const actual = jest.requireActual('crypto');
   return {
      ...actual,
      verify: jest.fn(),
   };
});

type MockMultiTenantService = {
   get: jest.Mock;
};

type MockTokenValidationService = {
   setNotBefore: jest.Mock;
};

type MockJwksCacheService = {
   getKey: jest.Mock;
};

type MockBackchannelLogoutService = {
   revoke: jest.Mock;
};

describe('KeycloakAdminService', () => {
   const realmUrl = 'https://kc/realms/master';
   const tenantConfig: ResolvedTenantConfig = {
      authServerUrl: 'https://kc',
      realm: 'master',
      clientId: 'api',
      secret: 'secret',
      realmUrl,
      realmAdminUrl: 'https://kc/admin/realms/master',
      isPublic: false,
      bearerOnly: true,
   };

   afterEach(() => {
      jest.restoreAllMocks();
      (crypto.verify as unknown as jest.Mock).mockReset();
   });

   const buildService = (opts: TestKeycloakConfig = { realm: 'master' }) => {
      const multiTenant: MockMultiTenantService = {
         get: jest.fn().mockResolvedValue(tenantConfig),
      };
      const tokenValidation: MockTokenValidationService = {
         setNotBefore: jest.fn(),
      };
      const jwksCache: MockJwksCacheService = {
         getKey: jest.fn().mockResolvedValue({} as crypto.KeyObject),
      };
      const backchannelLogoutService: MockBackchannelLogoutService = {
         revoke: jest.fn(),
      };

      const service = new KeycloakAdminService(
         tenantConfig,
         asKeycloakConfig(opts),
         asService<KeycloakMultiTenantService>(multiTenant),
         asService<TokenValidationService>(tokenValidation),
         asService<JwksCacheService>(jwksCache),
         asService<BackchannelLogoutService>(backchannelLogoutService),
      );

      return {
         service,
         multiTenant,
         tokenValidation,
         jwksCache,
         backchannelLogoutService,
      };
   };

   it('extractAdminPayload supports all payload formats', () => {
      const { service } = buildService();
      const req = {} as ServerRequest;

      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            ' token ',
            req,
         ),
      ).toBe('token');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            Buffer.from('token'),
            req,
         ),
      ).toBe('token');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            undefined,
            { rawBody: ' token ' },
         ),
      ).toBe('token');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            undefined,
            { rawBody: Buffer.from('token') },
         ),
      ).toBe('token');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            { token: ' token ' },
            req,
         ),
      ).toBe('token');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            { abc: '' },
            req,
         ),
      ).toBe('abc');
      expect(
         callPrivate<[unknown, ServerRequest], string | null>(
            service,
            'extractAdminPayload',
            {},
            req,
         ),
      ).toBeNull();
   });

   it('extractLogoutToken returns trimmed token and null for invalid inputs', () => {
      const { service } = buildService();

      expect(
         callPrivate<[unknown], string | null>(service, 'extractLogoutToken', {
            logout_token: ' token ',
         }),
      ).toBe('token');
      expect(
         callPrivate<[unknown], string | null>(service, 'extractLogoutToken', {
            logout_token: '',
         }),
      ).toBeNull();
      expect(
         callPrivate<[unknown], string | null>(service, 'extractLogoutToken', 'token'),
      ).toBeNull();
   });

   it('processPushNotBefore rejects invalid payload and unsigned token', async () => {
      const { service } = buildService();

      await expect(service.processPushNotBefore(undefined, {})).rejects.toThrow('invalid token');
      await expect(service.processPushNotBefore('bad-token', {})).rejects.toThrow('invalid token');
   });

   it('processPushNotBefore rejects expired token', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      jest.spyOn(Date, 'now').mockReturnValue(2000);
      const { service } = buildService();
      const token = makeJwt(
         { action: 'PUSH_NOT_BEFORE', notBefore: 1, iss: realmUrl, exp: 1 },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.processPushNotBefore(token, {})).rejects.toThrow('token expired');
   });

   it('processPushNotBefore rejects unsupported action and non-numeric notBefore', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      const { service } = buildService();

      const unsupportedToken = makeJwt(
         { action: 'OTHER', iss: realmUrl, exp: 9999999999 },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );
      await expect(service.processPushNotBefore(unsupportedToken, {})).rejects.toThrow(
         'unsupported action',
      );

      const invalidNotBeforeToken = makeJwt(
         {
            action: 'PUSH_NOT_BEFORE',
            notBefore: 'bad',
            iss: realmUrl,
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );
      await expect(service.processPushNotBefore(invalidNotBeforeToken, {})).rejects.toThrow(
         'invalid token',
      );
   });

   it('processPushNotBefore updates notBefore for valid callback', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      const { service, tokenValidation } = buildService();
      const token = makeJwt(
         {
            action: 'PUSH_NOT_BEFORE',
            notBefore: 123,
            iss: realmUrl,
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );

      await service.processPushNotBefore(token, {});
      expect(tokenValidation.setNotBefore).toHaveBeenCalledWith(123, realmUrl);
   });

   it('resolves tenant using async and sync realm resolvers', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      const tenantA: ResolvedTenantConfig = {
         ...tenantConfig,
         realm: 'tenant-a',
         realmUrl: 'https://kc/realms/tenant-a',
         realmAdminUrl: 'https://kc/admin/realms/tenant-a',
      };
      const { service, multiTenant, tokenValidation } = buildService({
         multiTenant: {
            realmResolver: jest.fn().mockResolvedValue('tenant-a'),
         },
      });
      multiTenant.get.mockResolvedValueOnce(tenantA);
      const token = makeJwt(
         {
            action: 'PUSH_NOT_BEFORE',
            notBefore: 5,
            iss: realmUrl,
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );

      await service.processPushNotBefore(token, { requestId: 1 });
      expect(multiTenant.get).toHaveBeenCalledWith('tenant-a', { requestId: 1 });
      expect(tokenValidation.setNotBefore).toHaveBeenCalledWith(5, tenantA.realmUrl);

      const { service: syncService, multiTenant: syncMultiTenant } = buildService({
         multiTenant: {
            realmResolver: () => 'tenant-sync',
         },
      });
      await syncService.processPushNotBefore(token, { requestId: 'sync' });
      expect(syncMultiTenant.get).toHaveBeenCalledWith('tenant-sync', { requestId: 'sync' });
   });

   it('rejects when realm resolver returns empty or throws', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      const token = makeJwt(
         {
            action: 'PUSH_NOT_BEFORE',
            notBefore: 1,
            iss: realmUrl,
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );

      const { service: emptyRealmService } = buildService({
         multiTenant: {
            realmResolver: jest.fn().mockResolvedValue(''),
         },
      });
      await expect(emptyRealmService.processPushNotBefore(token, {})).rejects.toThrow(
         'realm resolver returned an empty realm',
      );

      const { service: failingResolverService } = buildService({
         multiTenant: {
            realmResolver: jest.fn().mockRejectedValue(new Error('fail')),
         },
      });
      await expect(failingResolverService.processPushNotBefore(token, {})).rejects.toThrow(
         'cannot resolve tenant config',
      );
   });

   it('rejects when tenant resolution is impossible without realmResolver', async () => {
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      const { service } = buildService({ realm: undefined });
      const token = makeJwt(
         {
            action: 'PUSH_NOT_BEFORE',
            notBefore: 1,
            iss: 'https://kc/realms/from-iss',
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );

      await expect(service.processPushNotBefore(token, {})).rejects.toThrow(
         'cannot resolve realm',
      );
   });

   it('verifySignature rejects missing kid, jwks errors, and unsupported algs', async () => {
      const { service, jwksCache } = buildService();

      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(makeJwt({ iss: realmUrl }, { alg: 'RS256', typ: 'JWT' })),
            realmUrl,
         ),
      ).rejects.toThrow('missing token kid');

      jwksCache.getKey.mockRejectedValueOnce(new Error('jwks fail'));
      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(
               makeJwt({ iss: realmUrl }, { alg: 'RS256', typ: 'JWT', kid: 'kid-1' }),
            ),
            realmUrl,
         ),
      ).rejects.toThrow('failed to load public key to verify token');

      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(
               makeJwt({ iss: realmUrl }, { alg: 'UNKNOWN', typ: 'JWT', kid: 'kid-1' }),
            ),
            realmUrl,
         ),
      ).rejects.toThrow('unsupported token algorithm');
   });

   it('verifySignature validates RSA and PS algorithms and rejects bad signatures', async () => {
      const { service } = buildService();

      (crypto.verify as unknown as jest.Mock).mockReturnValueOnce(true);
      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(makeJwt({ iss: realmUrl }, { typ: 'JWT', kid: 'kid-1' })),
            realmUrl,
         ),
      ).resolves.toBeUndefined();
      expect(crypto.verify).toHaveBeenCalledWith(
         'SHA256',
         expect.any(Buffer),
         expect.any(Object),
         expect.any(Buffer),
      );

      (crypto.verify as unknown as jest.Mock).mockReturnValueOnce(true);
      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(
               makeJwt({ iss: realmUrl }, { alg: 'PS512', typ: 'JWT', kid: 'kid-1' }),
            ),
            realmUrl,
         ),
      ).resolves.toBeUndefined();
      expect(crypto.verify).toHaveBeenLastCalledWith(
         'SHA512',
         expect.any(Buffer),
         expect.objectContaining({
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
         }),
         expect.any(Buffer),
      );

      (crypto.verify as unknown as jest.Mock).mockReturnValueOnce(false);
      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(
               makeJwt({ iss: realmUrl }, { alg: 'RS256', typ: 'JWT', kid: 'kid-1' }),
            ),
            realmUrl,
         ),
      ).rejects.toThrow('invalid token (signature)');
      await expect(
         callPrivate<[KeycloakToken, string], Promise<void>>(
            service,
            'verifySignature',
            new KeycloakToken(
               makeJwt({ iss: realmUrl }, { alg: 'RS256', typ: 'JWT', kid: 'kid-1' }),
            ),
            realmUrl,
         ),
      ).rejects.toBeInstanceOf(KeycloakAdminError);
   });

   it('verifyTokenSignature falls back to SHA256 for unknown algorithm values', () => {
      const { service } = buildService();
      const keyObject = {} as crypto.KeyObject;
      (crypto.verify as unknown as jest.Mock).mockReturnValueOnce(true);

      const result = callPrivate<[string, Buffer, crypto.KeyObject, string], boolean>(
         service,
         'verifyTokenSignature',
         'signed',
         Buffer.from('sig'),
         keyObject,
         'UNKNOWN',
      );

      expect(result).toBe(true);
      expect(crypto.verify).toHaveBeenCalledWith(
         'SHA256',
         expect.any(Buffer),
         keyObject,
         expect.any(Buffer),
      );
   });

   it('processBackchannelLogout rejects invalid payloads and expired tokens', async () => {
      const { service } = buildService();

      await expect(service.processBackchannelLogout({}, {})).rejects.toThrow(
         'invalid logout token',
      );
      await expect(
         service.processBackchannelLogout({ logout_token: 'bad-token' }, {}),
      ).rejects.toThrow('invalid logout token');

      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);
      jest.spyOn(Date, 'now').mockReturnValue(2000);
      const expired = makeJwt(
         {
            iss: realmUrl,
            sid: 'sid-1',
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            exp: 1,
         },
         { alg: 'RS256', typ: 'logout+jwt', kid: 'kid-1' },
      );
      await expect(
         service.processBackchannelLogout({ logout_token: expired }, {}),
      ).rejects.toThrow('logout token expired');
   });

   it('processBackchannelLogout validates typ/events/sid-sub and revokes valid tokens', async () => {
      const { service, backchannelLogoutService } = buildService();
      (crypto.verify as unknown as jest.Mock).mockReturnValue(true);

      const invalidTyp = makeJwt(
         {
            iss: realmUrl,
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            sid: 'sid-1',
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'invalid', kid: 'kid-1' },
      );
      await expect(
         service.processBackchannelLogout({ logout_token: invalidTyp }, {}),
      ).rejects.toThrow('invalid logout token type');

      const missingEvent = makeJwt(
         { iss: realmUrl, sid: 'sid-1', events: {}, exp: 9999999999 },
         { alg: 'RS256', typ: 'logout+jwt', kid: 'kid-1' },
      );
      await expect(
         service.processBackchannelLogout({ logout_token: missingEvent }, {}),
      ).rejects.toThrow('missing backchannel-logout event');

      const missingSidSub = makeJwt(
         {
            iss: realmUrl,
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'logout+jwt', kid: 'kid-1' },
      );
      await expect(
         service.processBackchannelLogout({ logout_token: missingSidSub }, {}),
      ).rejects.toThrow('logout token must contain sid or sub');

      const both = makeJwt(
         {
            iss: realmUrl,
            sid: 'sid-1',
            sub: 'sub-1',
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'logout+jwt', kid: 'kid-1' },
      );
      await service.processBackchannelLogout({ logout_token: both }, {});
      expect(backchannelLogoutService.revoke).toHaveBeenCalledWith('sid-1', 'sub-1');

      const sidOnly = makeJwt(
         {
            iss: realmUrl,
            sid: 'sid-only',
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'JWT', kid: 'kid-1' },
      );
      await service.processBackchannelLogout({ logout_token: sidOnly }, {});
      expect(backchannelLogoutService.revoke).toHaveBeenCalledWith('sid-only', undefined);

      const subOnly = makeJwt(
         {
            iss: realmUrl,
            sub: 'sub-only',
            events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
            exp: 9999999999,
         },
         { alg: 'RS256', typ: 'logout+jwt', kid: 'kid-1' },
      );
      await service.processBackchannelLogout({ logout_token: subOnly }, {});
      expect(backchannelLogoutService.revoke).toHaveBeenCalledWith(undefined, 'sub-only');
   });

   it('uses KeycloakConfigError code semantics', async () => {
      const { service } = buildService();
      await expect(service.processPushNotBefore(undefined, {})).rejects.toMatchObject({
         code: 'KEYCLOAK_CONFIG_ERROR',
      });
      await expect(service.processPushNotBefore(undefined, {})).rejects.toBeInstanceOf(
         KeycloakConfigError,
      );
   });
});
