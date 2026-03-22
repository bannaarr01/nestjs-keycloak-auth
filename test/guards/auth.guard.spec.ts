import { Reflector } from '@nestjs/core';
import { TokenValidation } from '../../src/constants';
import { AuthGuard } from '../../src/guards/auth.guard';
import { KeycloakGrantService } from '../../src/services/keycloak-grant.service';
import { ResolvedTenantConfig } from '../../src/interface/tenant-config.interface';
import { TokenValidationService } from '../../src/services/token-validation.service';
import { BackchannelLogoutService } from '../../src/services/backchannel-logout.service';
import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
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
   headers: Record<string, string>;
   user?: Record<string, unknown>;
   accessToken?: string;
};

type MockTokenValidationService = {
   validateOnline: jest.MockedFunction<TokenValidationService['validateOnline']>;
   validateOffline: jest.MockedFunction<TokenValidationService['validateOffline']>;
};

type MockKeycloakGrantService = {
   createGrant: jest.Mock;
};

type MockBackchannelLogoutService = {
   isRevoked: jest.MockedFunction<BackchannelLogoutService['isRevoked']>;
};

type AuthGuardPrivateAccess = {
   validateToken: (tenantConfig: ResolvedTenantConfig, jwt: string) => Promise<boolean>;
};

describe('AuthGuard', () => {
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
      const tokenValidation: MockTokenValidationService = {
         validateOnline: jest.fn(),
         validateOffline: jest.fn(),
      };
      const keycloakGrant: MockKeycloakGrantService = {
         createGrant: jest.fn(),
      };
      const backchannelLogout: MockBackchannelLogoutService = {
         isRevoked: jest.fn().mockReturnValue(false),
      };
      const guard = new AuthGuard(
         singleTenant,
         asKeycloakConfig(opts),
         asService<KeycloakMultiTenantService>({}),
         asService<TokenValidationService>(tokenValidation),
         asService<KeycloakGrantService>(keycloakGrant),
         asService<BackchannelLogoutService>(backchannelLogout),
      );
      return { guard, tokenValidation, keycloakGrant, backchannelLogout };
   };

   const mockMetadata = (
      guard: AuthGuard,
      isPublic: boolean,
      requiredScopes?: string[],
   ) => {
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'public') {
               return isPublic;
            }
            if (key === 'token-scopes') {
               return requiredScopes;
            }
            return undefined;
         });
   };

   it('allows non-http contexts', async () => {
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

   it('throws on protected route without jwt', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false);
      const request: RequestLike = { headers: {} };

      await expect(guard.canActivate(makeContext(request))).rejects.toBeInstanceOf(
         UnauthorizedException,
      );
   });

   it('allows public route without jwt', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, true);
      const request: RequestLike = { headers: {} };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
   });

   it('authenticates and attaches user/accessToken when token is valid', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         preferred_username: 'john',
         exp: 9999999999,
      });
      const request: RequestLike = {
         headers: { authorization: `Bearer ${jwt}` },
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(request.accessToken).toBe(jwt);
      expect(request.user?.preferred_username).toBe('john');
   });

   it('allows public route when jwt is invalid', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, true);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(false);
      const request: RequestLike = {
         headers: { authorization: `Bearer ${makeJwt({ exp: 9999999999 })}` },
      };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
   });

   it('throws on protected route when jwt is invalid', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(false);
      const request: RequestLike = {
         headers: { authorization: `Bearer ${makeJwt({ exp: 9999999999 })}` },
      };

      await expect(guard.canActivate(makeContext(request))).rejects.toBeInstanceOf(
         UnauthorizedException,
      );
   });

   it('extractJwt handles empty/non-bearer/bearer headers', () => {
      const { guard } = buildGuard();
      expect(
         callPrivate<
            [Record<string, string | string[] | undefined>],
            string | null
         >(guard, 'extractJwt', {}),
      ).toBeNull();
      expect(
         callPrivate<
            [Record<string, string | string[] | undefined>],
            string | null
         >(guard, 'extractJwt', { authorization: 'Basic abc' }),
      ).toBeNull();
      expect(
         callPrivate<
            [Record<string, string | string[] | undefined>],
            string | null
         >(guard, 'extractJwt', { authorization: 'Bearer token' }),
      ).toBe('token');
   });

   it('validateToken handles ONLINE success and grant failure', async () => {
      const { guard, tokenValidation, keycloakGrant } = buildGuard({
         tokenValidation: TokenValidation.ONLINE,
      });
      keycloakGrant.createGrant.mockResolvedValue({});
      tokenValidation.validateOnline.mockResolvedValue(true);

      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            guard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(true);
      expect(keycloakGrant.createGrant).toHaveBeenCalledWith(
         { access_token: 'jwt' },
         singleTenant.realmUrl,
         singleTenant.clientId,
      );

      keycloakGrant.createGrant.mockRejectedValueOnce(new Error('bad grant'));
      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            guard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(false);
   });

   it('validateToken defaults to ONLINE when option is missing', async () => {
      const { guard, keycloakGrant, tokenValidation } = buildGuard({});
      keycloakGrant.createGrant.mockResolvedValue({});
      tokenValidation.validateOnline.mockResolvedValue(true);

      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            guard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(true);
   });

   it('validateToken handles OFFLINE/NONE/UNKNOWN and catch branch', async () => {
      const { guard, tokenValidation } = buildGuard({
         tokenValidation: TokenValidation.OFFLINE,
      });
      tokenValidation.validateOffline.mockResolvedValue(true);
      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            guard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(true);

      const { guard: noneGuard } = buildGuard({
         tokenValidation: TokenValidation.NONE,
      });
      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            noneGuard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(true);

      const { guard: unknownGuard } = buildGuard({
         tokenValidation: 'weird' as unknown as TestKeycloakConfig['tokenValidation'],
      });
      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            unknownGuard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(false);

      const { guard: catchGuard, keycloakGrant, tokenValidation: tv } = buildGuard({
         tokenValidation: TokenValidation.ONLINE,
      });
      keycloakGrant.createGrant.mockResolvedValue({});
      tv.validateOnline.mockRejectedValue(new Error('boom'));
      await expect(
         callPrivate<[ResolvedTenantConfig, string], Promise<boolean>>(
            catchGuard,
            'validateToken',
            singleTenant,
            'jwt',
         ),
      ).resolves.toBe(false);
   });

   it('throws unauthorized when revoked on protected route', async () => {
      const { guard, backchannelLogout } = buildGuard();
      mockMetadata(guard, false);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      backchannelLogout.isRevoked.mockReturnValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         sid: 's1',
         exp: 9999999999,
      });
      const request: RequestLike = { headers: { authorization: `Bearer ${jwt}` } };

      await expect(guard.canActivate(makeContext(request))).rejects.toBeInstanceOf(
         UnauthorizedException,
      );
   });

   it('allows public route and clears auth when revoked', async () => {
      const { guard, backchannelLogout } = buildGuard();
      mockMetadata(guard, true);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      backchannelLogout.isRevoked.mockReturnValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         sid: 's1',
         exp: 9999999999,
      });
      const request: RequestLike = { headers: { authorization: `Bearer ${jwt}` } };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
      expect(request.user).toBeUndefined();
      expect(request.accessToken).toBeUndefined();
   });

   it('enforces @TokenScopes and throws forbidden when missing', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false, ['email']);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         scope: 'openid profile',
         exp: 9999999999,
      });
      const request: RequestLike = { headers: { authorization: `Bearer ${jwt}` } };

      await expect(guard.canActivate(makeContext(request))).rejects.toBeInstanceOf(
         ForbiddenException,
      );
   });

   it('passes @TokenScopes check when all scopes are present', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false, ['openid', 'profile']);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         scope: 'openid profile',
         exp: 9999999999,
      });
      const request: RequestLike = { headers: { authorization: `Bearer ${jwt}` } };

      await expect(guard.canActivate(makeContext(request))).resolves.toBe(true);
   });

   it('treats non-string scope claim as empty and rejects required scopes', async () => {
      const { guard } = buildGuard();
      mockMetadata(guard, false, ['openid']);
      jest
         .spyOn(asService<AuthGuardPrivateAccess>(guard), 'validateToken')
         .mockResolvedValue(true);
      const jwt = makeJwt({
         sub: 'u1',
         scope: ['openid'],
         exp: 9999999999,
      });
      const request: RequestLike = { headers: { authorization: `Bearer ${jwt}` } };

      await expect(guard.canActivate(makeContext(request))).rejects.toBeInstanceOf(
         ForbiddenException,
      );
   });
});
