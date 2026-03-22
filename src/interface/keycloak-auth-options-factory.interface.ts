import { KeycloakAuthOptions } from './keycloak-auth-options.interface';

export interface KeycloakAuthOptionsFactory {
  createKeycloakAuthOptions():
    | Promise<KeycloakAuthOptions>
    | KeycloakAuthOptions;
}
