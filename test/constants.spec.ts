import {
   KEYCLOAK_AUTH_OPTIONS,
   KEYCLOAK_INSTANCE,
   KEYCLOAK_MULTITENANT_SERVICE,
   PolicyEnforcementMode,
   RoleMatch,
   RoleMerge,
   TokenValidation,
} from '../src/constants';


describe('constants', () => {
   it('exposes injection token constants', () => {
      expect(KEYCLOAK_AUTH_OPTIONS).toBe('KEYCLOAK_AUTH_OPTIONS');
      expect(KEYCLOAK_INSTANCE).toBe('KEYCLOAK_INSTANCE');
      expect(KEYCLOAK_MULTITENANT_SERVICE).toBe('KEYCLOAK_MULTITENANT_SERVICE');
   });

   it('exposes enums', () => {
      expect(RoleMatch.ALL).toBe('all');
      expect(RoleMatch.ANY).toBe('any');
      expect(PolicyEnforcementMode.ENFORCING).toBe('enforcing');
      expect(PolicyEnforcementMode.PERMISSIVE).toBe('permissive');
      expect(TokenValidation.ONLINE).toBe('online');
      expect(TokenValidation.OFFLINE).toBe('offline');
      expect(TokenValidation.NONE).toBe('none');
      expect(RoleMerge.OVERRIDE).toBe(0);
      expect(RoleMerge.ALL).toBe(1);
   });
});
