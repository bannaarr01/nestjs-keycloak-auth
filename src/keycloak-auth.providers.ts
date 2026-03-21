import * as fs from 'fs';
import * as path from 'path';
import { Provider } from '@nestjs/common';
import { KeycloakAuthModule } from './keycloak-auth.module';
import { ResolvedTenantConfig } from './interface/tenant-config.interface';
import {
   KEYCLOAK_AUTH_OPTIONS,
   KEYCLOAK_INSTANCE,
   TokenValidation,
} from './constants';
import {
   KeycloakAuthConfig,
   KeycloakAuthOptions,
   NestKeycloakConfig,
} from './interface/keycloak-auth-options.interface';

/**
 * Resolve environment variable references in config values.
 * Matches keycloak-connect config.js resolveValue() logic.
 * Supports: ${env.MY_VAR} and ${env.MY_VAR:fallback}
 */
function resolveValue(value: unknown): unknown {
   if (typeof value !== 'string') {
      return value;
   }

   const regex = /\$\{env\.([^:]*):?(.*)?\}/;
   if (!regex.test(value)) {
      return value;
   }

   const tokens = value.replace(regex, '$1--split--$2').split('--split--');
   const envVar = tokens[0];
   const envVal = process.env[envVar];
   const fallbackVal = tokens[1];

   return envVal || fallbackVal;
}

/**
 * Resolves a KeycloakAuthConfig into a ResolvedTenantConfig.
 */
const resolveConfig = (opts: KeycloakAuthConfig): ResolvedTenantConfig => {
   const authServerUrl = (
    resolveValue(
       opts.authServerUrl ||
        opts['auth-server-url'] ||
        opts.serverUrl ||
        opts['server-url'] ||
        '',
    ) as string
   ).replace(/\/+$/, '');
   const realm = resolveValue(opts.realm || '') as string;
   const clientId = resolveValue(
      opts.clientId || opts['client-id'] || opts.resource || '',
   ) as string;
   const secret = resolveValue(
      opts.secret || (opts.credentials && opts.credentials.secret) || '',
   ) as string;
   const realmUrl = realm ? `${authServerUrl}/realms/${realm}` : authServerUrl;
   const realmAdminUrl = realm
      ? `${authServerUrl}/admin/realms/${realm}`
      : authServerUrl;
   const isPublic = !!resolveValue(
      opts['public-client'] ?? opts.public ?? false,
   );
   const bearerOnly = !!resolveValue(
      opts['bearer-only'] ?? opts.bearerOnly ?? false,
   );

   return {
      authServerUrl,
      realm,
      clientId,
      secret,
      realmUrl,
      realmAdminUrl,
      isPublic,
      bearerOnly,
   };
};

export const keycloakProvider: Provider = {
   provide: KEYCLOAK_INSTANCE,
   useFactory: (opts: KeycloakAuthOptions): ResolvedTenantConfig => {
      if (typeof opts === 'string') {
         throw new Error(
            'Keycloak configuration should have been parsed by this point.',
         );
      }

      // Warn if using token validation none
      if (opts.tokenValidation && opts.tokenValidation === TokenValidation.NONE) {
         KeycloakAuthModule.logger.warn(
            'Token validation is disabled, please only do this on development/special use-cases.',
         );
      }

      return resolveConfig(opts);
   },
   inject: [KEYCLOAK_AUTH_OPTIONS],
};

const parseConfig = (
   opts: KeycloakAuthOptions,
   config?: NestKeycloakConfig,
): KeycloakAuthConfig => {
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

export const createKeycloakAuthOptionProvider = (
   opts: KeycloakAuthOptions,
   config?: NestKeycloakConfig,
) => {
   return {
      provide: KEYCLOAK_AUTH_OPTIONS,
      useValue: parseConfig(opts, config),
   };
};
