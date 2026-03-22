import {
   KeycloakAdminError,
   KeycloakAuthError,
   KeycloakConfigError,
   KeycloakPermissionError,
   KeycloakTokenError,
} from '../src/errors';


describe('errors', () => {
   it('creates KeycloakAuthError with default and custom codes', () => {
      const withDefaultCode = new KeycloakAuthError('base');
      expect(withDefaultCode.message).toBe('base');
      expect(withDefaultCode.code).toBe('KEYCLOAK_AUTH_ERROR');
      expect(withDefaultCode.name).toBe('KeycloakAuthError');

      const withCustomCode = new KeycloakAuthError('base', 'CUSTOM_CODE');
      expect(withCustomCode.code).toBe('CUSTOM_CODE');
   });

   it('creates specialized error classes with stable codes', () => {
      expect(new KeycloakConfigError('c').code).toBe('KEYCLOAK_CONFIG_ERROR');
      expect(new KeycloakTokenError('t').code).toBe('KEYCLOAK_TOKEN_ERROR');
      expect(new KeycloakPermissionError('p').code).toBe('KEYCLOAK_PERMISSION_ERROR');
      expect(new KeycloakAdminError('a').code).toBe('KEYCLOAK_ADMIN_ERROR');
   });
});
