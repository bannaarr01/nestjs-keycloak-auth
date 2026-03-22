import { Product } from './product';
import { ExampleUser } from '../../interface/example-user.interface';
import { buildTenantClaims, ProductService } from './product.service';
import { ProductRequest } from '../../interface/product-request.interface';
import { Body, Controller, Delete, Get, Headers, Param, Post, Put, Req } from '@nestjs/common';
import {
   AccessToken,
   ConditionalScopes,
   EnforcerOptions,
   KeycloakUser,
   ResolvedScopes,
   Resource,
   Roles,
   Scopes,
   TokenScopes,
} from 'nestjs-keycloak-auth';

@Controller('product')
@Resource(Product.name)
export class ProductController {
  constructor(private readonly service: ProductService) {}

  @Get()
  @ConditionalScopes((request, token) => {
    if (token.hasRealmRole('basic')) {
      return ['View'];
    }
    if (token.hasRealmRole('admin')) {
      return ['View.All'];
    }
    return [];
  })
  findAll(@ResolvedScopes() scopes: string[]) {
    return this.service.findAllByScopes(scopes);
  }

  @Get('uma/permissions')
  @Scopes('View')
  @TokenScopes('openid')
  @EnforcerOptions({
    response_mode: 'permissions',
    claims: buildTenantClaims,
  })
  permissionsMode(
    @Req() request: ProductRequest,
    @ResolvedScopes() scopes: string[],
    @KeycloakUser() user: ExampleUser | undefined,
  ) {
    return this.service.permissionsMode(request, scopes, user);
  }

  @Get('uma/token/:code')
  @Scopes('View')
  @TokenScopes('openid')
  @EnforcerOptions({
    response_mode: 'token',
    claims: buildTenantClaims,
  })
  tokenMode(
    @Param('code') code: string,
    @AccessToken() accessToken: string | undefined,
  ) {
    return this.service.tokenMode(code, accessToken);
  }

  @Get('uma/decision')
  @Scopes('View')
  @EnforcerOptions({
    response_mode: 'decision',
    resource_server_id: 'nest-api',
    claims: buildTenantClaims,
  })
  decisionMode(
    @Headers('x-tenant-realm') tenantRealm: string | undefined,
    @ResolvedScopes() scopes: string[],
  ) {
    return this.service.decisionMode(tenantRealm, scopes);
  }

  @Get(':code')
  @Roles('realm:basic', 'basic', 'realm:admin')
  findByCode(
    @Param('code') code: string,
    @KeycloakUser() user: ExampleUser | undefined,
  ) {
    return this.service.findByCodeWithUser(code, user);
  }

  @Post()
  @Scopes('Create')
  @TokenScopes('openid')
  create(@Body() product: Product) {
    return this.service.create(product);
  }

  @Delete(':code')
  @Scopes('Delete')
  @TokenScopes('openid')
  deleteByCode(@Param('code') code: string) {
    return this.service.deleteByCode(code);
  }

  @Put(':code')
  @Scopes('Edit')
  @TokenScopes('openid')
  update(@Param('code') code: string, @Body() product: Product) {
    return this.service.update(code, product);
  }
}
