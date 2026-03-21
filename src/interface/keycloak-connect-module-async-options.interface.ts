import { ModuleMetadata, Type } from '@nestjs/common/interfaces';
import { KeycloakConnectOptions } from './keycloak-connect-options.interface';
import { KeycloakConnectOptionsFactory } from './keycloak-connect-options-factory.interface';
import { InjectionToken } from '@nestjs/common/interfaces/modules/injection-token.interface';
import { OptionalFactoryDependency } from '@nestjs/common/interfaces/modules/optional-factory-dependency.interface';

export interface KeycloakConnectModuleAsyncOptions
  extends Pick<ModuleMetadata, 'imports'> {
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
  useExisting?: Type<KeycloakConnectOptionsFactory>;
  useClass?: Type<KeycloakConnectOptionsFactory>;
  useFactory?: (
    ...args: unknown[]
  ) => Promise<KeycloakConnectOptions> | KeycloakConnectOptions;
}
