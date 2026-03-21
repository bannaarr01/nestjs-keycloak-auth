import { Provider } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import {
  KEYCLOAK_CONNECT_OPTIONS,
  KEYCLOAK_INSTANCE,
  TokenValidation,
} from './constants';
import {
  KeycloakConnectConfig,
  KeycloakConnectOptions,
  NestKeycloakConfig,
} from './interface/keycloak-connect-options.interface';
import { ResolvedTenantConfig } from './interface/tenant-config.interface';
import { KeycloakConnectModule } from './keycloak-connect.module';

/**
 * Resolves a KeycloakConnectConfig into a ResolvedTenantConfig.
 */
const resolveConfig = (opts: KeycloakConnectConfig): ResolvedTenantConfig => {
  const authServerUrl =
    opts.authServerUrl ||
    opts['auth-server-url'] ||
    opts.serverUrl ||
    opts['server-url'] ||
    '';
  const realm = opts.realm || '';
  const clientId = opts.clientId || opts['client-id'] || opts.resource || '';
  const secret =
    opts.secret || (opts.credentials && opts.credentials.secret) || '';
  const realmUrl = realm
    ? `${authServerUrl.replace(/\/$/, '')}/realms/${realm}`
    : authServerUrl;

  return { authServerUrl, realm, clientId, secret, realmUrl };
};

export const keycloakProvider: Provider = {
  provide: KEYCLOAK_INSTANCE,
  useFactory: (opts: KeycloakConnectOptions): ResolvedTenantConfig => {
    if (typeof opts === 'string') {
      throw new Error(
        'Keycloak configuration should have been parsed by this point.',
      );
    }

    // Warn if using token validation none
    if (opts.tokenValidation && opts.tokenValidation === TokenValidation.NONE) {
      KeycloakConnectModule.logger.warn(
        'Token validation is disabled, please only do this on development/special use-cases.',
      );
    }

    return resolveConfig(opts);
  },
  inject: [KEYCLOAK_CONNECT_OPTIONS],
};

const parseConfig = (
  opts: KeycloakConnectOptions,
  config?: NestKeycloakConfig,
): KeycloakConnectConfig => {
  if (typeof opts === 'string') {
    const configPathRelative = path.join(__dirname, opts);
    const configPathRoot = path.join(process.cwd(), opts);

    let configPath: string;

    if (fs.existsSync(configPathRelative)) {
      configPath = configPathRelative;
    } else if (fs.existsSync(configPathRoot)) {
      configPath = configPathRoot;
    } else {
      throw new Error(
        `Cannot find files, looked in [ ${configPathRelative}, ${configPathRoot} ]`,
      );
    }

    const json = fs.readFileSync(configPath);
    const keycloakConfig = JSON.parse(json.toString());
    return Object.assign(keycloakConfig, config);
  }
  return opts;
};

export const createKeycloakConnectOptionProvider = (
  opts: KeycloakConnectOptions,
  config?: NestKeycloakConfig,
) => {
  return {
    provide: KEYCLOAK_CONNECT_OPTIONS,
    useValue: parseConfig(opts, config),
  };
};
