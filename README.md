<div align="center">

# NestJS Keycloak Auth

![GitHub Issues or Pull Requests](https://img.shields.io/github/issues/bannaarr01/nestjs-keycloak-auth?style=for-the-badge)
![GitHub License](https://img.shields.io/github/license/bannaarr01/nestjs-keycloak-auth?style=for-the-badge)

A bearer-only Keycloak authentication and authorization module for [NestJS](https://nestjs.com/). Uses standard OIDC discovery and has zero runtime dependency on `keycloak-connect`.

> **Attribution:** This project is a fork of [nest-keycloak-connect](https://github.com/ferrerojosh/nest-keycloak-connect) by [John Joshua Ferrer](https://github.com/ferrerojosh). Licensed under MIT.

</div>

## Features

- Bearer-token API authentication and authorization for NestJS.
- OIDC discovery — endpoints resolved from `.well-known/openid-configuration` (with fallback).
- ONLINE and OFFLINE token validation (introspection + JWKS signature verification).
- Per-realm `notBefore` revocation state for multi-tenant safety.
- Resource/scope authorization via UMA (`@Resource`, `@Scopes`, `@ConditionalScopes`).
- Role authorization (`@Roles`) with configurable role merge and match modes.
- Compatible with [Fastify](https://github.com/fastify/fastify) platform.

## Runtime Scope (Important)

- This package is designed for bearer-only API/server flows.
- It does **not** implement browser/session middleware flows such as login redirects, auth-code callback exchange, session/cookie grant stores, or logout endpoints.
- It does implement `POST /k_push_not_before` to receive Keycloak admin revocation updates (used by OFFLINE token validation).

## Installation

### Yarn

```bash
yarn add nestjs-keycloak-auth
```

### NPM

```bash
npm install nestjs-keycloak-auth --save
```

## Getting Started

### Module registration

Registering the module:

```typescript
KeycloakConnectModule.register({
  authServerUrl: 'http://localhost:8080', // might be http://localhost:8080/auth for older keycloak versions
  realm: 'master',
  clientId: 'my-nestjs-app',
  secret: 'secret',
  bearerOnly: true,
  policyEnforcement: PolicyEnforcementMode.PERMISSIVE, // optional
  tokenValidation: TokenValidation.ONLINE, // optional
});
```

Async registration is also available:

```typescript
KeycloakConnectModule.registerAsync({
  useExisting: KeycloakConfigService,
  imports: [ConfigModule],
});
```

#### KeycloakConfigService

```typescript
import { Injectable } from '@nestjs/common';
import {
  KeycloakConnectOptions,
  KeycloakConnectOptionsFactory,
  PolicyEnforcementMode,
  TokenValidation,
} from 'nestjs-keycloak-auth';

@Injectable()
export class KeycloakConfigService implements KeycloakConnectOptionsFactory {
  createKeycloakConnectOptions(): KeycloakConnectOptions {
    return {
      // http://localhost:8080/auth for older keycloak versions
      authServerUrl: 'http://localhost:8080',
      realm: 'master',
      clientId: 'my-nestjs-app',
      secret: 'secret',
      bearerOnly: true,
      policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
      tokenValidation: TokenValidation.ONLINE,
    };
  }
}
```

You can also register by just providing the `keycloak.json` path and an optional module configuration:

```typescript
KeycloakConnectModule.register(`./keycloak.json`, {
  policyEnforcement: PolicyEnforcementMode.PERMISSIVE,
  tokenValidation: TokenValidation.ONLINE,
});
```

### Guards

Register any of the guards either globally, or scoped in your controller.

#### Global registration using APP_GUARD token

**_NOTE: These are in order, see https://docs.nestjs.com/guards#binding-guards for more information._**

```typescript
providers: [
  {
    provide: APP_GUARD,
    useClass: AuthGuard,
  },
  {
    provide: APP_GUARD,
    useClass: ResourceGuard,
  },
  {
    provide: APP_GUARD,
    useClass: RoleGuard,
  },
];
```

#### Scoped registration

```typescript
@Controller('cats')
@UseGuards(AuthGuard, ResourceGuard)
export class CatsController {}
```

## What does these providers do ?

### AuthGuard

Adds an authentication guard, you can also have it scoped if you like (using regular `@UseGuards(AuthGuard)` in your controllers). By default, it will throw a 401 unauthorized when it is unable to verify the JWT token or `Bearer` header is missing.

### ResourceGuard

Adds a resource guard, which is permissive by default (can be configured see [options](#nest-keycloak-options)). Only controllers annotated with `@Resource` and methods with `@Scopes` are handled by this guard.

When `@EnforcerOptions()` is not provided, default claims are sent for authorization requests:
- `http.uri`
- `user.agent`

**_NOTE: This guard is not necessary if you are using role-based authorization exclusively. You can use role guard exclusively for that._**

### RoleGuard

Adds a role guard, **can only be used in conjunction with resource guard when enforcement policy is PERMISSIVE**, unless you only use role guard exclusively.
Permissive by default. Used by controller methods annotated with `@Roles` (matching can be configured)

## Configuring controllers

In your controllers, simply do:

```typescript
import {
  Resource,
  Roles,
  Scopes,
  Public,
  RoleMatchingMode,
} from 'nestjs-keycloak-auth';
import { Controller, Get, Delete, Put, Post, Param } from '@nestjs/common';
import { Product } from './product';
import { ProductService } from './product.service';

@Controller()
@Resource(Product.name)
export class ProductController {
  constructor(private service: ProductService) {}

  @Get()
  @Public()
  async findAll() {
    return await this.service.findAll();
  }

  @Get()
  @Roles({ roles: ['admin', 'other'] })
  async findAllBarcodes() {
    return await this.service.findAllBarcodes();
  }

  @Get(':code')
  @Scopes('View')
  async findByCode(@Param('code') code: string) {
    return await this.service.findByCode(code);
  }

  @Post()
  @Scopes('Create')
  @ConditionalScopes((request, token) => {
    if (token.hasRealmRole('sysadmin')) {
      return ['Overwrite'];
    }
    return [];
  })
  async create(@Body() product: Product) {
    return await this.service.create(product);
  }

  @Delete(':code')
  @Scopes('Delete')
  @Roles({ roles: ['admin', 'realm:sysadmin'], mode: RoleMatchingMode.ALL })
  async deleteByCode(@Param('code') code: string) {
    return await this.service.deleteByCode(code);
  }

  @Put(':code')
  @Scopes('Edit')
  async update(@Param('code') code: string, @Body() product: Product) {
    return await this.service.update(code, product);
  }
}
```

## Decorators

Here is the decorators you can use in your controllers.

| Decorator          | Description                                                                                               |
| ------------------ | --------------------------------------------------------------------------------------------------------- |
| @KeycloakUser      | Retrieves the current Keycloak logged-in user. (must be per method, unless controller is request scoped.) |
| @AccessToken       | Retrieves the access token used in the request                                                            |
| @ResolvedScopes    | Retrieves the resolved scopes (used in @ConditionalScopes)                                                |
| @EnforcerOptions   | Keycloak enforcer options.                                                                                |
| @Public            | Allow any user to use the route.                                                                          |
| @Resource          | Keycloak application resource name.                                                                       |
| @Scopes            | Keycloak application scopes.                                                                              |
| @ConditionalScopes | Conditional keycloak application scopes.                                                                  |
| @Roles             | Keycloak realm/application roles.                                                                         |

## Multi tenant configuration

Setting up for multi-tenant is configured as an option in your configuration:

```typescript
{
  // Add /auth for older keycloak versions
  authServerUrl: 'http://localhost:8180/', // will be used as fallback
  clientId: 'nest-api', // will be used as fallback
  secret: 'fallback', // will be used as fallback
  multiTenant: {
    resolveAlways: true,
    realmResolver: (request) => {
      return request.get('host').split('.')[0];
    },
    realmSecretResolver: (realm, request) => {
      const secrets = { master: 'secret', slave: 'password' };
      return secrets[realm];
    },
    realmClientIdResolver: (realm, request) => {
      const clientIds = { master: 'angular-app', slave: 'vue-app' };
      return clientIds[realm];
    },
    // note to add /auth for older keycloak versions
    realmAuthServerUrlResolver: (realm, request) => {
      const authServerUrls = { master: 'https://master.local/', slave: 'https://slave.local/' };
      return authServerUrls[realm];
    }
  }
}
```

## Admin callback endpoint

This module mounts a Keycloak admin callback endpoint:

- `POST /k_push_not_before`

Purpose:

- Accepts signed Keycloak admin callbacks with action `PUSH_NOT_BEFORE`.
- Updates token revocation cutoff (`notBefore`) used by OFFLINE validation.
- Stores `notBefore` per realm URL, so one realm update does not affect another realm in multi-tenant setups.

Realm resolution for callback verification:

1. `multiTenant.realmResolver(request)` when configured
2. single-tenant configured realm (`realm`)
3. fallback to callback token issuer (`iss`) realm

`k_logout` is intentionally not implemented because there is no session/cookie grant storage layer to invalidate.

## Configuration options

### Nest Keycloak Options

| Option            | Description                                                                | Required | Default    |
| ----------------- | -------------------------------------------------------------------------- | -------- | ---------- |
| policyEnforcement | Sets the policy enforcement mode                                           | no       | PERMISSIVE |
| tokenValidation   | Sets the token validation method                                           | no       | ONLINE     |
| multiTenant       | Sets options for [multi-tenant configuration](#multi-tenant-configuration) | no       | -          |
| roleMerge         | Sets the merge mode for `@Roles` decorator                                | no       | OVERRIDE   |

### Common Keycloak Config Fields

| Option                         | Description                                            |
| ------------------------------ | ------------------------------------------------------ |
| `realm`                        | Realm name                                             |
| `clientId` / `client-id`       | Client ID (or `resource`)                              |
| `secret` / `credentials.secret` | Client secret (confidential clients)                  |
| `authServerUrl` / `serverUrl`  | Keycloak base URL                                      |
| `bearerOnly` / `bearer-only`   | Marks bearer-only behavior                             |
| `public` / `public-client`     | Public client mode                                     |
| `realmPublicKey`               | Static realm public key for OFFLINE validation         |
| `verifyTokenAudience`          | Enables strict audience check in OFFLINE validation    |
| `minTimeBetweenJwksRequests`   | JWKS retry throttle                                    |

### Multi Tenant Options

| Option                     | Description                                                                                               | Required | Default |
| -------------------------- | --------------------------------------------------------------------------------------------------------- | -------- | ------- |
| resolveAlways              | Always resolve realm config instead of using cached values                                                | no       | false   |
| realmResolver              | Resolves realm from request                                                                               | yes      | -       |
| realmSecretResolver        | Resolves secret by realm (and optional request)                                                           | no       | -       |
| realmAuthServerUrlResolver | Resolves auth server URL by realm (and optional request)                                                  | no       | -       |
| realmClientIdResolver      | Resolves client ID by realm (and optional request)                                                        | yes      | -       |

## Example app

An [example application](example) is provided in the source code with both Keycloak Realm and Postman requests for you to experiment with.
