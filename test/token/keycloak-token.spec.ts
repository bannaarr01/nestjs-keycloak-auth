import { makeJwt } from '../helpers';
import { KeycloakToken } from '../../src/token/keycloak-token';

describe('KeycloakToken', () => {
   afterEach(() => {
      jest.restoreAllMocks();
   });

   it('parses token fields', () => {
      const jwt = makeJwt({
         exp: 9999999999,
         typ: 'Bearer',
         realm_access: { roles: ['admin'] },
      });

      const token = new KeycloakToken(jwt, 'api');

      expect(token.header.alg).toBe('RS256');
      expect(token.content.typ).toBe('Bearer');
      expect(token.signed).toContain('.');
      expect(token.signature).toBeInstanceOf(Buffer);
      expect(token.token).toBe(jwt);
      expect(token.toString()).toBe(jwt);
   });

   it('handles malformed JWT safely', () => {
      const token = new KeycloakToken('bad');
      expect(token.content.exp).toBe(0);
   });

   it('allows empty token input without parsing', () => {
      const token = new KeycloakToken('');
      expect(token.token).toBe('');
   });

   it('checks role with default client prefixless syntax', () => {
      const jwt = makeJwt({
         exp: 9999999999,
         resource_access: { api: { roles: ['writer'] } },
      });
      const token = new KeycloakToken(jwt, 'api');

      expect(token.hasRole('writer')).toBe(true);
      expect(token.hasRole('reader')).toBe(false);
   });

   it('checks realm role syntax', () => {
      const jwt = makeJwt({
         exp: 9999999999,
         realm_access: { roles: ['sysadmin'] },
      });
      const token = new KeycloakToken(jwt, 'api');

      expect(token.hasRole('realm:sysadmin')).toBe(true);
      expect(token.hasRole('realm:user')).toBe(false);
   });

   it('checks explicit client role syntax', () => {
      const jwt = makeJwt({
         exp: 9999999999,
         resource_access: { svc: { roles: ['manager'] } },
      });
      const token = new KeycloakToken(jwt, 'api');

      expect(token.hasRole('svc:manager')).toBe(true);
      expect(token.hasRole('svc:viewer')).toBe(false);
   });

   it('returns false for role checks without clientId context', () => {
      const jwt = makeJwt({ exp: 9999999999 });
      const token = new KeycloakToken(jwt);

      expect(token.hasRole('arbitrary-role')).toBe(false);
   });

   it('checks realm role helpers', () => {
      const tokenNoRealm = new KeycloakToken(makeJwt({ exp: 9999999999 }), 'api');
      expect(tokenNoRealm.hasRealmRole('x')).toBe(false);

      const tokenRealm = new KeycloakToken(
         makeJwt({ exp: 9999999999, realm_access: { roles: ['x'] } }),
         'api',
      );
      expect(tokenRealm.hasRealmRole('x')).toBe(true);
   });

   it('checks application role helpers', () => {
      const noResource = new KeycloakToken(makeJwt({ exp: 9999999999 }), 'api');
      expect(noResource.hasApplicationRole('api', 'x')).toBe(false);

      const noClient = new KeycloakToken(
         makeJwt({ exp: 9999999999, resource_access: { other: { roles: ['x'] } } }),
         'api',
      );
      expect(noClient.hasApplicationRole('api', 'x')).toBe(false);

      const yes = new KeycloakToken(
         makeJwt({ exp: 9999999999, resource_access: { api: { roles: ['x'] } } }),
         'api',
      );
      expect(yes.hasApplicationRole('api', 'x')).toBe(true);
   });

   it('checks permissions with and without scopes', () => {
      const payload = {
         exp: 9999999999,
         authorization: {
            permissions: [
               { rsid: 'orders', scopes: ['view'] },
               { rsname: 'invoices' },
            ],
         },
      };
      const token = new KeycloakToken(makeJwt(payload), 'api');

      expect(token.hasPermission('orders')).toBe(true);
      expect(token.hasPermission('orders', 'view')).toBe(true);
      expect(token.hasPermission('orders', 'edit')).toBe(false);
      expect(token.hasPermission('invoices', 'sample-scope')).toBe(true);
      expect(token.hasPermission('unknown')).toBe(false);
   });

   it('returns false when authorization block is absent', () => {
      const token = new KeycloakToken(makeJwt({ exp: 9999999999 }), 'api');
      expect(token.hasPermission('orders')).toBe(false);
   });

   it('checks expiration based on exp', () => {
      const nowSpy = jest.spyOn(Date, 'now').mockReturnValue(1000);
      const valid = new KeycloakToken(makeJwt({ exp: 2 }), 'api');
      const expired = new KeycloakToken(makeJwt({ exp: 0 }), 'api');

      expect(valid.isExpired()).toBe(false);
      expect(expired.isExpired()).toBe(true);
      nowSpy.mockRestore();
   });
});
