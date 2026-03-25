import { RoleMatch } from '../constants';
import { SetMetadata } from '@nestjs/common';
import { RolesDecoratorInput } from '../types/roles-decorator-input.type';
import { RolesDecoratorOptions } from '../interface/roles-decorator-options.interface';

export const META_ROLES = 'roles';
export const META_ROLE_MATCHING_MODE = 'role-matching-mode';

function isRolesDecoratorOptions(value: unknown): value is RolesDecoratorOptions {
   return (
      typeof value === 'object' &&
      value !== null &&
      !Array.isArray(value) &&
      Array.isArray((value as RolesDecoratorOptions).roles)
   );
}

function normalizeRoles(args: RolesDecoratorInput[]): string[] {
   if (args.length === 0) return [];

   const first = args[0];

   if (isRolesDecoratorOptions(first)) return first.roles;
   if (Array.isArray(first)) return first;

   return args as string[];
}

/**
 * Keycloak user roles.
 *
 * @example
 * // Variadic strings
 * \ @Roles('admin', 'basic')
 *
 * // Single string
 * \ @Roles('admin')
 *
 * // Array of strings
 * \ @Roles(['admin', 'basic'])
 *
 * // Options object with roles key
 * \ @Roles({ roles: ['realm:admin', 'realm:basic'] })
 *
 * @param args - the roles to match. Accepts variadic strings, a single array, or an options object with a `roles` key.
 * @since 2.0.0
 */
export const Roles = (...args: RolesDecoratorInput[]) =>
   SetMetadata(META_ROLES, normalizeRoles(args));

export const RoleMatchingMode = (mode: RoleMatch) =>
   SetMetadata(META_ROLE_MATCHING_MODE, mode);
