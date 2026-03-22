import { AppService } from './app.service';
import { Controller, Get, Headers } from '@nestjs/common';
import { ExampleUser } from './interface/example-user.interface';
import {
   Public,
   Roles,
   RoleMatch,
   TokenScopes,
   AccessToken,
   KeycloakUser,
   RoleMatchingMode,
} from 'nestjs-keycloak-auth';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Public()
  getHello(@KeycloakUser() user: ExampleUser | undefined) {
    return this.appService.getHello(user);
  }

  @Get('private')
  @TokenScopes('openid')
  getPrivate(
    @KeycloakUser() user: ExampleUser | undefined,
    @AccessToken() accessToken: string | undefined,
  ) {
    return this.appService.getPrivate(user, accessToken);
  }

  @Get('me')
  @TokenScopes('openid', 'profile')
  getCurrentUser(@KeycloakUser() user: ExampleUser | undefined) {
    return this.appService.getCurrentUser(user);
  }

  @Get('roles/any')
  @Roles('realm:basic', 'basic')
  @RoleMatchingMode(RoleMatch.ANY)
  basicRoleAny(@KeycloakUser() user: ExampleUser | undefined) {
    return this.appService.basicRoleAny(user);
  }

  @Get('roles/all')
  @Roles('realm:basic', 'basic')
  @RoleMatchingMode(RoleMatch.ALL)
  basicRoleAll(@KeycloakUser() user: ExampleUser | undefined) {
    return this.appService.basicRoleAll(user);
  }

  @Get('roles/admin')
  @Roles('realm:admin')
  @RoleMatchingMode(RoleMatch.ANY)
  adminRole(@KeycloakUser() user: ExampleUser | undefined) {
    return this.appService.adminRole(user);
  }

  @Get('tenant')
  @Public()
  tenantHint(
    @Headers('x-tenant-realm') tenantRealm: string | undefined,
    @Headers('host') host: string | undefined,
  ) {
    return this.appService.tenantHint(tenantRealm, host);
  }
}
