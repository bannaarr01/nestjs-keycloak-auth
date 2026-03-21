import { Inject, Injectable } from '@nestjs/common';
import { KEYCLOAK_CONNECT_OPTIONS } from '../constants';
import { ResolvedTenantConfig } from '../interface/tenant-config.interface';
import { KeycloakConnectOptions } from '../interface/keycloak-connect-options.interface';

/**
 * Stores resolved tenant configurations for multi-tenant scenarios.
 */
@Injectable()
export class KeycloakMultiTenantService {
  private configs: Map<string, ResolvedTenantConfig> = new Map();

  constructor(
    @Inject(KEYCLOAK_CONNECT_OPTIONS)
    private keycloakOpts: KeycloakConnectOptions,
  ) {}

  /**
   * Clears the cached tenant configurations.
   */
  clear() {
    this.configs.clear();
  }

  /**
   * Retrieves a resolved tenant config based on the realm provided.
   * @param realm the realm to retrieve from
   * @param request the request instance, defaults to undefined
   * @returns the resolved tenant configuration
   */
  async get(
    realm: string,
    request: unknown = undefined,
  ): Promise<ResolvedTenantConfig> {
    if (typeof this.keycloakOpts === 'string') {
      throw new Error(
        'Keycloak configuration is a configuration path. This should not happen after module load.',
      );
    }
    if (
      this.keycloakOpts.multiTenant === null ||
      this.keycloakOpts.multiTenant === undefined
    ) {
      throw new Error(
        'Multi tenant is not defined yet multi tenant service is being called.',
      );
    }

    const authServerUrl = await this.resolveAuthServerUrl(realm, request);
    const secret = await this.resolveSecret(realm, request);
    const clientId = await this.resolveClientId(realm, request);

    // Check if existing
    if (
      this.configs.has(realm) &&
      !this.keycloakOpts.multiTenant.resolveAlways
    ) {
      return this.configs.get(realm);
    } else {
      const realmUrl = `${authServerUrl.replace(/\/$/, '')}/realms/${realm}`;

      const realmAdminUrl = `${authServerUrl.replace(/\/$/, '')}/admin/realms/${realm}`;
      const isPublic =
        typeof this.keycloakOpts !== 'string' &&
        !!(
          this.keycloakOpts['public-client'] ??
          this.keycloakOpts.public ??
          false
        );
      const bearerOnly =
        typeof this.keycloakOpts !== 'string' &&
        !!(
          this.keycloakOpts['bearer-only'] ??
          this.keycloakOpts.bearerOnly ??
          false
        );

      const config: ResolvedTenantConfig = {
        authServerUrl,
        realm,
        clientId,
        secret,
        realmUrl,
        realmAdminUrl,
        isPublic,
        bearerOnly,
      };

      this.configs.set(realm, config);
      return config;
    }
  }

  async resolveAuthServerUrl(
    realm: string,
    request: unknown = undefined,
  ): Promise<string> {
    if (typeof this.keycloakOpts === 'string') {
      throw new Error(
        'Keycloak configuration is a configuration path. This should not happen after module load.',
      );
    }
    if (
      this.keycloakOpts.multiTenant === null ||
      this.keycloakOpts.multiTenant === undefined
    ) {
      throw new Error(
        'Multi tenant is not defined yet multi tenant service is being called.',
      );
    }

    // If no realm auth server url resolver is defined, return defaults
    if (!this.keycloakOpts.multiTenant.realmAuthServerUrlResolver) {
      return (
        this.keycloakOpts.authServerUrl ||
        this.keycloakOpts['auth-server-url'] ||
        this.keycloakOpts.serverUrl ||
        this.keycloakOpts['server-url']
      );
    }

    // Resolve realm authServerUrl
    const resolvedAuthServerUrl =
      this.keycloakOpts.multiTenant.realmAuthServerUrlResolver(realm, request);
    const authServerUrl =
      resolvedAuthServerUrl || resolvedAuthServerUrl instanceof Promise
        ? await resolvedAuthServerUrl
        : resolvedAuthServerUrl;

    // Override auth server url
    // Order of priority: resolved realm auth server url > provided auth server url
    return (
      authServerUrl ||
      this.keycloakOpts.authServerUrl ||
      this.keycloakOpts['auth-server-url'] ||
      this.keycloakOpts.serverUrl ||
      this.keycloakOpts['server-url']
    );
  }

  async resolveClientId(
    realm: string,
    request: unknown = undefined,
  ): Promise<string> {
    if (typeof this.keycloakOpts === 'string') {
      throw new Error(
        'Keycloak configuration is a configuration path. This should not happen after module load.',
      );
    }
    if (
      this.keycloakOpts.multiTenant === null ||
      this.keycloakOpts.multiTenant === undefined
    ) {
      throw new Error(
        'Multi tenant is not defined yet multi tenant service is being called.',
      );
    }

    // If no realm client-id resolver is defined, return defaults
    if (!this.keycloakOpts.multiTenant.realmClientIdResolver) {
      return this.keycloakOpts.clientId || this.keycloakOpts['client-id'];
    }

    // Resolve realm client-id
    const resolvedClientId =
      this.keycloakOpts.multiTenant.realmClientIdResolver(realm, request);
    const realmClientId =
      resolvedClientId || resolvedClientId instanceof Promise
        ? await resolvedClientId
        : resolvedClientId;

    // Override client-id
    // Order of priority: resolved realm secret > default global secret
    return (
      realmClientId ||
      this.keycloakOpts.clientId ||
      this.keycloakOpts['client-id']
    );
  }

  async resolveSecret(
    realm: string,
    request: unknown = undefined,
  ): Promise<string> {
    if (typeof this.keycloakOpts === 'string') {
      throw new Error(
        'Keycloak configuration is a configuration path. This should not happen after module load.',
      );
    }
    if (
      this.keycloakOpts.multiTenant === null ||
      this.keycloakOpts.multiTenant === undefined
    ) {
      throw new Error(
        'Multi tenant is not defined yet multi tenant service is being called.',
      );
    }

    // If no realm secret resolver is defined, return defaults
    if (!this.keycloakOpts.multiTenant.realmSecretResolver) {
      return this.keycloakOpts.secret;
    }

    // Resolve realm secret
    const resolvedRealmSecret =
      this.keycloakOpts.multiTenant.realmSecretResolver(realm, request);
    const realmSecret =
      resolvedRealmSecret || resolvedRealmSecret instanceof Promise
        ? await resolvedRealmSecret
        : resolvedRealmSecret;

    // Override secret
    // Order of priority: resolved realm secret > default global secret
    return realmSecret || this.keycloakOpts.secret;
  }
}
