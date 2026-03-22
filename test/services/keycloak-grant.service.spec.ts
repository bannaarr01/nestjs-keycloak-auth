import { asKeycloakConfig, asService, makeJwt } from '../helpers';
import { KeycloakGrantService } from '../../src/services/keycloak-grant.service';
import { TokenValidationService } from '../../src/services/token-validation.service';

type MockTokenValidationService = {
   validateOffline: jest.MockedFunction<TokenValidationService['validateOffline']>;
};

describe('KeycloakGrantService', () => {
   it('creates and validates grant from object', async () => {
      const tokenValidation: MockTokenValidationService = {
         validateOffline: jest.fn().mockResolvedValue(true),
      };
      const service = new KeycloakGrantService(
         asKeycloakConfig({ clientId: 'client-a' }),
         asService<TokenValidationService>(tokenValidation),
      );

      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 1, iss: 'realm' });
      const grant = await service.createGrant(
         { access_token: jwt, expires_in: 10, token_type: 'Bearer' },
         'realm',
      );

      expect(tokenValidation.validateOffline).toHaveBeenCalledWith(
         jwt,
         'realm',
         'client-a',
         'Bearer',
      );
      expect(grant.access_token?.token).toBe(jwt);
      expect(grant.expires_in).toBe(10);
      expect(grant.token_type).toBe('Bearer');
   });

   it('creates and validates grant from raw string and fallback client id fields', async () => {
      const tokenValidation: MockTokenValidationService = {
         validateOffline: jest.fn().mockResolvedValue(true),
      };
      const service = new KeycloakGrantService(
         asKeycloakConfig({ 'client-id': 'client-b' }),
         asService<TokenValidationService>(tokenValidation),
      );

      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 1, iss: 'realm' });
      const grant = await service.createGrant(
         JSON.stringify({ access_token: jwt }),
         'realm',
      );

      expect(grant.access_token?.token).toBe(jwt);
      expect(tokenValidation.validateOffline).toHaveBeenCalledWith(
         jwt,
         'realm',
         'client-b',
         'Bearer',
      );
   });

   it('supports resource as client id fallback and empty access token grant', async () => {
      const tokenValidation: MockTokenValidationService = {
         validateOffline: jest.fn().mockResolvedValue(true),
      };
      const service = new KeycloakGrantService(
         asKeycloakConfig({ resource: 'resource-client' }),
         asService<TokenValidationService>(tokenValidation),
      );

      const grant = await service.createGrant({}, 'realm');

      expect(grant.access_token).toBeUndefined();
      expect(tokenValidation.validateOffline).not.toHaveBeenCalled();
   });

   it('throws when access token validation fails', async () => {
      const tokenValidation: MockTokenValidationService = {
         validateOffline: jest.fn().mockResolvedValue(false),
      };
      const service = new KeycloakGrantService(
         asKeycloakConfig({ clientId: 'client-a' }),
         asService<TokenValidationService>(tokenValidation),
      );
      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 1, iss: 'realm' });

      await expect(
         service.createGrant({ access_token: jwt }, 'realm', undefined, 'secret'),
      ).rejects.toThrow('Grant validation failed. Reason: invalid access_token');
   });

   it('uses provided clientId override in createGrant/validateGrant', async () => {
      const tokenValidation: MockTokenValidationService = {
         validateOffline: jest.fn().mockResolvedValue(true),
      };
      const service = new KeycloakGrantService(
         asKeycloakConfig({}),
         asService<TokenValidationService>(tokenValidation),
      );
      const jwt = makeJwt({ exp: 9999999999, typ: 'Bearer', iat: 1, iss: 'realm' });

      await service.createGrant({ access_token: jwt }, 'realm', 'override-client');
      expect(tokenValidation.validateOffline).toHaveBeenCalledWith(
         jwt,
         'realm',
         'override-client',
         'Bearer',
      );

      tokenValidation.validateOffline.mockClear();
      const grant = await service.createGrant({ access_token: jwt }, 'realm');
      await service.validateGrant(grant, 'realm', 'explicit-client');
      expect(tokenValidation.validateOffline).toHaveBeenLastCalledWith(
         jwt,
         'realm',
         'explicit-client',
         'Bearer',
      );
   });
});
