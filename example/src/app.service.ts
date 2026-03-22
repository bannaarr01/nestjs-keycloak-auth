import { Injectable } from '@nestjs/common';
import { ExampleUser } from './interface/example-user.interface';

@Injectable()
export class AppService {
  getHello(user: ExampleUser | undefined) {
    return {
      message: user ? `Hello ${user.preferred_username ?? 'authenticated-user'}` : 'Hello world!',
      authenticated: Boolean(user),
      callbacks: {
        pushNotBefore: '/k_push_not_before',
        backchannelLogout: '/k_logout',
      },
    };
  }

  getPrivate(
    user: ExampleUser | undefined,
    accessToken: string | undefined,
  ) {
    return {
      message: 'Authenticated only',
      sub: user?.sub ?? null,
      username: user?.preferred_username ?? null,
      tokenPreview: accessToken ? `${accessToken.slice(0, 16)}...` : null,
    };
  }

  getCurrentUser(user: ExampleUser | undefined) {
    return {
      user: user ?? null,
    };
  }

  basicRoleAny(user: ExampleUser | undefined) {
    return {
      message: 'Matched at least one role: realm:basic OR basic',
      username: user?.preferred_username ?? null,
    };
  }

  basicRoleAll(user: ExampleUser | undefined) {
    return {
      message: 'Matched both roles: realm:basic + basic',
      username: user?.preferred_username ?? null,
    };
  }

  adminRole(user: ExampleUser | undefined) {
    return {
      message: 'Admin role only',
      username: user?.preferred_username ?? null,
    };
  }

  tenantHint(
    tenantRealm: string | undefined,
    host: string | undefined,
  ) {
    return {
      note: 'Set x-tenant-realm to force multi-tenant realm selection in resolvers',
      tenantRealmHeader: tenantRealm ?? null,
      host: host ?? null,
    };
  }
}
