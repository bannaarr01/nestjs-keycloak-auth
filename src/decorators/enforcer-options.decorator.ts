import { SetMetadata } from '@nestjs/common';
import { KeycloakEnforcerOptions } from '../interface/enforcer-options.interface';

export const META_ENFORCER_OPTIONS = 'enforcer-options';

/**
 * Keycloak enforcer options
 * @param opts - enforcer options
 * @since 1.3.0
 */
export const EnforcerOptions = (opts: KeycloakEnforcerOptions) =>
   SetMetadata(META_ENFORCER_OPTIONS, opts);
