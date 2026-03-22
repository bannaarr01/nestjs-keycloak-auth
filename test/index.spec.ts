import * as api from '../src';

describe('public index', () => {
   it('re-exports module symbols', () => {
      expect(api.KeycloakAuthModule).toBeDefined();
      expect(api.AuthGuard).toBeDefined();
      expect(api.ResourceGuard).toBeDefined();
      expect(api.RoleGuard).toBeDefined();
   });
});
