import { Injectable, Logger } from '@nestjs/common';

/**
 * In-memory store tracking revoked sessions and users from
 * OIDC back-channel logout tokens.
 *
 * Entries are automatically cleaned up after the configured TTL
 * (default 24 hours) to prevent unbounded memory growth.
 */
@Injectable()
export class BackchannelLogoutService {
   private readonly logger = new Logger(BackchannelLogoutService.name);

   private readonly revokedSessions = new Map<string, number>(); // sid → revokedAt
   private readonly revokedUsers = new Map<string, number>(); // sub → revokedAt

   private readonly ttlMs = 24 * 60 * 60 * 1000; // 24 hours

   /**
   * Mark a session and/or user as revoked.
   * At least one of `sid` or `sub` must be provided.
   */
   revoke(sid?: string, sub?: string): void {
      const now = Date.now();

      if (sid) {
         this.revokedSessions.set(sid, now);
         this.logger.log(`Session revoked: ${sid}`);
      }

      if (sub) {
         this.revokedUsers.set(sub, now);
         this.logger.log(`User revoked: ${sub}`);
      }

      this.cleanup();
   }

   /**
   * Check whether a session or user has been revoked.
   * @param sid  Session ID from the token
   * @param sub  Subject (user ID) from the token
   * @param iat  Issued-at timestamp (seconds) from the token — tokens issued
   *             after the revocation are from a new session and should be allowed.
   */
   isRevoked(sid?: string, sub?: string, iat?: number): boolean {
      const cutoff = Date.now() - this.ttlMs;
      const issuedAtMs = iat ? iat * 1000 : 0;

      if (sid) {
         const revokedAt = this.revokedSessions.get(sid);
         if (revokedAt !== undefined) {
            if (revokedAt < cutoff) {
               this.revokedSessions.delete(sid);
            } else {
               return true;
            }
         }
      }

      if (sub) {
         const revokedAt = this.revokedUsers.get(sub);
         if (revokedAt !== undefined) {
            if (revokedAt < cutoff) {
               this.revokedUsers.delete(sub);
            } else if (issuedAtMs > revokedAt) {
               // Token was issued after the revocation — new session, allow it
               return false;
            } else {
               return true;
            }
         }
      }

      return false;
   }

   /**
   * Remove entries older than the TTL to prevent unbounded growth.
   */
   private cleanup(): void {
      const cutoff = Date.now() - this.ttlMs;

      for (const [key, revokedAt] of this.revokedSessions) {
         if (revokedAt < cutoff) {
            this.revokedSessions.delete(key);
         }
      }

      for (const [key, revokedAt] of this.revokedUsers) {
         if (revokedAt < cutoff) {
            this.revokedUsers.delete(key);
         }
      }
   }
}
