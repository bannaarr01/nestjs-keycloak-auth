import { HttpModule } from '@nestjs/axios';
import { JwksCacheService } from './services/jwks-cache.service';
import { KeycloakHttpService } from './services/keycloak-http.service';
import { KeycloakGrantService } from './services/keycloak-grant.service';
import { OidcDiscoveryService } from './services/oidc-discovery.service';
import { KeycloakAdminService } from './services/keycloak-admin.service';
import { DynamicModule, Logger, Module, Provider } from '@nestjs/common';
import { TokenValidationService } from './services/token-validation.service';
import { KEYCLOAK_AUTH_OPTIONS, KEYCLOAK_MULTITENANT_SERVICE } from './constants';
import { BackchannelLogoutService } from './services/backchannel-logout.service';
import { KeycloakAdminController } from './controllers/keycloak-admin.controller';
import { KeycloakMultiTenantService } from './services/keycloak-multitenant.service';
import { createKeycloakAuthOptionProvider, keycloakProvider } from './keycloak-auth.providers';
import { KeycloakAuthOptions, NestKeycloakConfig } from './interface/keycloak-auth-options.interface';
import { KeycloakAuthOptionsFactory } from './interface/keycloak-auth-options-factory.interface';
import { KeycloakAuthModuleAsyncOptions } from './interface/keycloak-auth-module-async-options.interface';

export * from './constants';
export * from './decorators/access-token.decorator';
export * from './decorators/enforcer-options.decorator';
export * from './decorators/keycloak-user.decorator';
export * from './decorators/public.decorator';
export * from './decorators/resource.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/scopes.decorator';
export * from './decorators/token-scopes.decorator';
export * from './guards/auth.guard';
export * from './guards/resource.guard';
export * from './guards/role.guard';
export * from './interface/jwt.interface';
export * from './interface/keycloak-auth-module-async-options.interface';
export * from './interface/keycloak-auth-options-factory.interface';
export * from './interface/keycloak-auth-options.interface';
export * from './interface/keycloak-request.interface';
export * from './interface/oidc.interface';
export * from './interface/server.interface';
export * from './interface/tenant-config.interface';
export * from './interface/enforcer-options.interface';
export * from './interface/jwks.interface';
export * from './interface/keycloak-grant.interface';
export * from './services/keycloak-multitenant.service';
export * from './services/oidc-discovery.service';
export * from './services/keycloak-http.service';
export * from './services/keycloak-url.service';
export * from './services/keycloak-grant.service';
export * from './services/jwks-cache.service';
export * from './services/token-validation.service';
export * from './services/backchannel-logout.service';
export * from './services/keycloak-admin.service';
export * from './controllers/keycloak-admin.controller';
export * from './token/keycloak-token';
export * from './token/keycloak-grant';
export * from './types/conditional-scope.type';
export * from './errors';
export * from './util';

@Module({})
export class KeycloakAuthModule {
   static logger = new Logger(KeycloakAuthModule.name);

   /**
   * Register the `KeycloakAuth` module.
   * @param opts `keycloak.json` path in string or {@link NestKeycloakConfig} object.
   * @param config {@link NestKeycloakConfig} when using `keycloak.json` path, optional
   * @returns
   */
   public static register(
      opts: KeycloakAuthOptions,
      config?: NestKeycloakConfig,
   ): DynamicModule {
      const keycloakConnectProviders = [
         createKeycloakAuthOptionProvider(opts, config),
         keycloakProvider,
         KeycloakMultiTenantService,
         {
            provide: KEYCLOAK_MULTITENANT_SERVICE,
            useClass: KeycloakMultiTenantService,
         },
         OidcDiscoveryService,
         KeycloakHttpService,
         KeycloakGrantService,
         JwksCacheService,
         TokenValidationService,
         BackchannelLogoutService,
         KeycloakAdminService,
      ];
      return {
         module: KeycloakAuthModule,
         imports: [HttpModule],
         controllers: [KeycloakAdminController],
         providers: keycloakConnectProviders,
         exports: keycloakConnectProviders,
      };
   }

   public static registerAsync(
      opts: KeycloakAuthModuleAsyncOptions,
   ): DynamicModule {
      const optsProvider = this.createAsyncProviders(opts);

      return {
         module: KeycloakAuthModule,
         imports: [...(opts.imports || []), HttpModule],
         controllers: [KeycloakAdminController],
         providers: optsProvider,
         exports: optsProvider,
      };
   }

   private static createAsyncProviders(
      options: KeycloakAuthModuleAsyncOptions,
   ): Provider[] {
      const reqProviders = [
         this.createAsyncOptionsProvider(options),
         keycloakProvider,
         KeycloakMultiTenantService,
         {
            provide: KEYCLOAK_MULTITENANT_SERVICE,
            useClass: KeycloakMultiTenantService,
         },
         OidcDiscoveryService,
         KeycloakHttpService,
         KeycloakGrantService,
         JwksCacheService,
         TokenValidationService,
         BackchannelLogoutService,
         KeycloakAdminService,
      ];

      if (options.useExisting || options.useFactory) {
         return reqProviders;
      }

      return [
         ...reqProviders,
         {
            provide: options.useClass,
            useClass: options.useClass,
         },
      ];
   }

   private static createAsyncOptionsProvider(
      options: KeycloakAuthModuleAsyncOptions,
   ): Provider {
      if (options.useFactory) {
         return {
            provide: KEYCLOAK_AUTH_OPTIONS,
            useFactory: options.useFactory,
            inject: options.inject || [],
         };
      }

      return {
         provide: KEYCLOAK_AUTH_OPTIONS,
         useFactory: async (optionsFactory: KeycloakAuthOptionsFactory) =>
            await optionsFactory.createKeycloakAuthOptions(),
         inject: [options.useExisting || options.useClass],
      };
   }
}
