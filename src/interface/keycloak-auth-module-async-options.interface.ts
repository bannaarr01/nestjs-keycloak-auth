import { ModuleMetadata, Type } from '@nestjs/common/interfaces';
import { KeycloakAuthOptions } from './keycloak-auth-options.interface';
import { KeycloakAuthOptionsFactory } from './keycloak-auth-options-factory.interface';
import { InjectionToken } from '@nestjs/common/interfaces/modules/injection-token.interface';
import { OptionalFactoryDependency } from '@nestjs/common/interfaces/modules/optional-factory-dependency.interface';

export interface KeycloakAuthModuleAsyncOptions
  extends Pick<ModuleMetadata, 'imports'> {
  inject?: Array<InjectionToken | OptionalFactoryDependency>;
  useExisting?: Type<KeycloakAuthOptionsFactory>;
  useClass?: Type<KeycloakAuthOptionsFactory>;
  useFactory?: (
    ...args: unknown[]
  ) => Promise<KeycloakAuthOptions> | KeycloakAuthOptions;
}
