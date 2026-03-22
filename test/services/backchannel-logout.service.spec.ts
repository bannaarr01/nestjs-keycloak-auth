import { getPrivate } from '../helpers';
import { BackchannelLogoutService } from '../../src/services/backchannel-logout.service';

describe('BackchannelLogoutService', () => {
   afterEach(() => {
      jest.restoreAllMocks();
   });

   it('revokes session and user and reports revoked state', () => {
      jest.spyOn(Date, 'now').mockReturnValue(1000);
      const service = new BackchannelLogoutService();

      service.revoke('sid-1', 'sub-1');

      expect(service.isRevoked('sid-1')).toBe(true);
      expect(service.isRevoked(undefined, 'sub-1')).toBe(true);
      expect(service.isRevoked('sid-2', 'sub-2')).toBe(false);
   });

   it('supports revoking only sid or only sub', () => {
      const service = new BackchannelLogoutService();
      service.revoke('sid-only');
      service.revoke(undefined, 'sub-only');

      expect(service.isRevoked('sid-only')).toBe(true);
      expect(service.isRevoked(undefined, 'sub-only')).toBe(true);
   });

   it('returns false for unknown/falsy sub values', () => {
      const service = new BackchannelLogoutService();

      expect(service.isRevoked(undefined, 'missing-sub')).toBe(false);
      expect(service.isRevoked(undefined, '')).toBe(false);
   });

   it('cleans up old revoked entries based on ttl', () => {
      const service = new BackchannelLogoutService();
      const revokedSessions = getPrivate<Map<string, number>>(service, 'revokedSessions');
      const revokedUsers = getPrivate<Map<string, number>>(service, 'revokedUsers');
      const ttlMs = getPrivate<number>(service, 'ttlMs');

      revokedSessions.set('old-sid', 1000);
      revokedUsers.set('old-sub', 1000);

      jest.spyOn(Date, 'now').mockReturnValue(1000 + ttlMs + 1);
      service.revoke('new-sid', 'new-sub');

      expect(revokedSessions.has('old-sid')).toBe(false);
      expect(revokedUsers.has('old-sub')).toBe(false);
      expect(revokedSessions.has('new-sid')).toBe(true);
      expect(revokedUsers.has('new-sub')).toBe(true);
   });

   it('allows tokens issued after user revocation (new session)', () => {
      const revokeTime = 1_000_000;
      jest.spyOn(Date, 'now').mockReturnValue(revokeTime);
      const service = new BackchannelLogoutService();
      service.revoke('old-sid', 'user-sub');

      // Token issued before revocation — should be revoked
      const iatBefore = (revokeTime - 5000) / 1000; // seconds
      expect(service.isRevoked('other-sid', 'user-sub', iatBefore)).toBe(true);

      // Token issued after revocation — new session, should be allowed
      const iatAfter = (revokeTime + 5000) / 1000; // seconds
      expect(service.isRevoked('new-sid', 'user-sub', iatAfter)).toBe(false);

      // Old session ID is still revoked regardless of iat
      expect(service.isRevoked('old-sid', 'user-sub', iatAfter)).toBe(true);
   });

   it('removes stale sid/sub entries during isRevoked checks', () => {
      const service = new BackchannelLogoutService();
      const revokedSessions = getPrivate<Map<string, number>>(service, 'revokedSessions');
      const revokedUsers = getPrivate<Map<string, number>>(service, 'revokedUsers');
      const ttlMs = getPrivate<number>(service, 'ttlMs');

      revokedSessions.set('stale-sid', 1000);
      revokedUsers.set('stale-sub', 1000);

      jest.spyOn(Date, 'now').mockReturnValue(1000 + ttlMs + 1);

      expect(service.isRevoked('stale-sid', 'stale-sub')).toBe(false);
      expect(revokedSessions.has('stale-sid')).toBe(false);
      expect(revokedUsers.has('stale-sub')).toBe(false);
   });
});
