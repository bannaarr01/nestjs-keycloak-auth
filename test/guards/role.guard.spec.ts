import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { RoleGuard } from '../../src/guards/role.guard';
import { RoleMatch, RoleMerge } from '../../src/constants';
import { ResolvedTenantConfig } from '../../src/interface/tenant-config.interface';
import { KeycloakMultiTenantService } from '../../src/services/keycloak-multitenant.service';
import { asKeycloakConfig, asService, getPrivate, makeContext, makeJwt, TestKeycloakConfig } from '../helpers';

describe('RoleGuard', () => {
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
      const guard = new RoleGuard(
         singleTenant,
         asKeycloakConfig(opts),
         asService<KeycloakMultiTenantService>({}),
      );
      return guard;
   };

   it('returns true when no roles are configured', async () => {
      const guard = buildGuard({ realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation(() => undefined);

      await expect(guard.canActivate(makeContext({ accessToken: 'x' }))).resolves.toBe(
         true,
      );
   });

   it('throws for unknown role merge value', async () => {
      const guard = buildGuard({
         roleMerge: 999 as unknown as RoleMerge,
         realm: 'master',
      });
      await expect(
         guard.canActivate(makeContext({ accessToken: 'x' })),
      ).rejects.toThrow('Unknown role merge: 999');
   });

   it('supports RoleMerge.ALL and RoleMatch.ANY', async () => {
      const guard = buildGuard({ roleMerge: RoleMerge.ALL, realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest.spyOn(reflector, 'getAllAndMerge').mockReturnValue(['writer']);
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'role-matching-mode') {
               return RoleMatch.ANY;
            }
            return undefined;
         });
      const token = makeJwt({
         exp: 9999999999,
         resource_access: { api: { roles: ['writer'] } },
      });

      await expect(
         guard.canActivate(makeContext({ accessToken: token })),
      ).resolves.toBe(true);
   });

   it('returns true when RoleMerge.ALL has no merged roles', async () => {
      const guard = buildGuard({ roleMerge: RoleMerge.ALL, realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest.spyOn(reflector, 'getAllAndMerge').mockReturnValue(undefined);
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation(() => undefined);

      await expect(
         guard.canActivate(makeContext({ accessToken: 'token' })),
      ).resolves.toBe(true);
   });

   it('supports RoleMerge.OVERRIDE and RoleMatch.ALL', async () => {
      const guard = buildGuard({ roleMerge: RoleMerge.OVERRIDE, realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'role-matching-mode') {
               return RoleMatch.ALL;
            }
            if (key === 'roles') {
               return ['writer', 'reader'];
            }
            return undefined;
         });
      const token = makeJwt({
         exp: 9999999999,
         resource_access: { api: { roles: ['writer'] } },
      });

      await expect(
         guard.canActivate(makeContext({ accessToken: token })),
      ).resolves.toBe(false);
   });

   it('returns true for non-http context', async () => {
      const guard = buildGuard({ roleMerge: RoleMerge.OVERRIDE, realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'roles') {
               return ['writer'];
            }
            return undefined;
         });
      const context = {
         getType: () => 'rpc',
         getClass: () => class A {},
         getHandler: () => () => undefined,
      };

      await expect(guard.canActivate(context as unknown as ExecutionContext)).resolves.toBe(
         true,
      );
   });

   it('returns false when accessToken is missing', async () => {
      const guard = buildGuard({ roleMerge: RoleMerge.OVERRIDE, realm: 'master' });
      const reflector = getPrivate<Reflector>(guard, 'reflector');
      jest
         .spyOn(reflector, 'getAllAndOverride')
         .mockImplementation((key: string) => {
            if (key === 'roles') {
               return ['writer'];
            }
            return undefined;
         });

      await expect(guard.canActivate(makeContext({}))).resolves.toBe(false);
   });
});
