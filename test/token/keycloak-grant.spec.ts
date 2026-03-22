import { KeycloakGrant } from '../../src/token/keycloak-grant';
import { KeycloakToken } from '../../src/token/keycloak-token';

describe('KeycloakGrant', () => {
   it('updates fields and returns raw string', () => {
      const grant = new KeycloakGrant({
         token_type: 'Bearer',
         expires_in: 100,
         __raw: '{"a":1}',
      });

      expect(grant.token_type).toBe('Bearer');
      expect(grant.expires_in).toBe(100);
      expect(grant.toString()).toBe('{"a":1}');

      const token = { isExpired: () => false } as unknown as KeycloakToken;
      grant.update({
         access_token: token,
         token_type: 'Updated',
         expires_in: 200,
         __raw: '{"a":2}',
      });
      expect(grant.access_token).toBe(token);
      expect(grant.token_type).toBe('Updated');
      expect(grant.expires_in).toBe(200);
      expect(grant.toString()).toBe('{"a":2}');
   });

   it('is expired when access token is missing', () => {
      const grant = new KeycloakGrant({});
      expect(grant.isExpired()).toBe(true);
   });

   it('delegates expiration to access token', () => {
      const grant = new KeycloakGrant({
         access_token: { isExpired: () => false } as unknown as KeycloakToken,
      });
      expect(grant.isExpired()).toBe(false);
   });
});
