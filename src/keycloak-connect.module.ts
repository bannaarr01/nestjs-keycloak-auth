import { ProxyModule } from './proxy/proxy.module';
import { JwksCacheService } from './services/jwks-cache.service';
import { KeycloakUrlService } from './services/keycloak-url.service';
import { KeycloakHttpService } from './services/keycloak-http.service';
import { KeycloakGrantService } from './services/keycloak-grant.service';
import { DynamicModule, Logger, Module, Provider } from '@nestjs/common';
import { TokenValidationService } from './services/token-validation.service';
import { KeycloakAdminController } from './controllers/keycloak-admin.controller';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_MULTITENANT_SERVICE,
} from './constants';
import { KeycloakMultiTenantService } from './services/keycloak-multitenant.service';
import {
  createKeycloakConnectOptionProvider,
  keycloakProvider,
} from './keycloak-connect.providers';
import { KeycloakConnectOptionsFactory } from './interface/keycloak-connect-options-factory.interface';
import {
  KeycloakConnectOptions,
  NestKeycloakConfig,
} from './interface/keycloak-connect-options.interface';
import { KeycloakConnectModuleAsyncOptions } from './interface/keycloak-connect-module-async-options.interface';

export * from './constants';
export * from './decorators/access-token.decorator';
export * from './decorators/enforcer-options.decorator';
export * from './decorators/keycloak-user.decorator';
export * from './decorators/public.decorator';
export * from './decorators/resource.decorator';
export * from './decorators/roles.decorator';
export * from './decorators/scopes.decorator';
export * from './guards/auth.guard';
export * from './guards/resource.guard';
export * from './guards/role.guard';
export * from './interface/keycloak-connect-module-async-options.interface';
export * from './interface/keycloak-connect-options-factory.interface';
export * from './interface/keycloak-connect-options.interface';
export * from './interface/tenant-config.interface';
export * from './interface/enforcer-options.interface';
export * from './interface/jwks.interface';
export * from './interface/keycloak-grant.interface';
export * from './services/keycloak-multitenant.service';
export * from './services/keycloak-http.service';
export * from './services/keycloak-url.service';
export * from './services/keycloak-grant.service';
export * from './services/jwks-cache.service';
export * from './services/token-validation.service';
export * from './controllers/keycloak-admin.controller';
export * from './token/keycloak-token';
export * from './token/keycloak-grant';
export * from './util';

@Module({})
export class KeycloakConnectModule {
  static logger = new Logger(KeycloakConnectModule.name);

  /**
   * Register the `KeycloakConnect` module.
   * @param opts `keycloak.json` path in string or {@link NestKeycloakConfig} object.
   * @param config {@link NestKeycloakConfig} when using `keycloak.json` path, optional
   * @returns
   */
  public static register(
    opts: KeycloakConnectOptions,
    config?: NestKeycloakConfig,
  ): DynamicModule {
    const keycloakConnectProviders = [
      createKeycloakConnectOptionProvider(opts, config),
      keycloakProvider,
      KeycloakMultiTenantService,
      {
        provide: KEYCLOAK_MULTITENANT_SERVICE,
        useClass: KeycloakMultiTenantService,
      },
      KeycloakHttpService,
      KeycloakUrlService,
      KeycloakGrantService,
      JwksCacheService,
      TokenValidationService,
    ];
    return {
      module: KeycloakConnectModule,
      imports: [ProxyModule],
      controllers: [KeycloakAdminController],
      providers: keycloakConnectProviders,
      exports: keycloakConnectProviders,
    };
  }

  public static registerAsync(
    opts: KeycloakConnectModuleAsyncOptions,
  ): DynamicModule {
    const optsProvider = this.createAsyncProviders(opts);

    return {
      module: KeycloakConnectModule,
      imports: [...(opts.imports || []), ProxyModule],
      controllers: [KeycloakAdminController],
      providers: optsProvider,
      exports: optsProvider,
    };
  }

  private static createAsyncProviders(
    options: KeycloakConnectModuleAsyncOptions,
  ): Provider[] {
    const reqProviders = [
      this.createAsyncOptionsProvider(options),
      keycloakProvider,
      KeycloakMultiTenantService,
      {
        provide: KEYCLOAK_MULTITENANT_SERVICE,
        useClass: KeycloakMultiTenantService,
      },
      KeycloakHttpService,
      KeycloakUrlService,
      KeycloakGrantService,
      JwksCacheService,
      TokenValidationService,
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
    options: KeycloakConnectModuleAsyncOptions,
  ): Provider {
    if (options.useFactory) {
      return {
        provide: KEYCLOAK_CONNECT_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }

    return {
      provide: KEYCLOAK_CONNECT_OPTIONS,
      useFactory: async (optionsFactory: KeycloakConnectOptionsFactory) =>
        await optionsFactory.createKeycloakConnectOptions(),
      inject: [options.useExisting || options.useClass],
    };
  }
}
