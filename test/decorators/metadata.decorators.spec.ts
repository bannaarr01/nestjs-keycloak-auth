import 'reflect-metadata';
import { RoleMatch } from '../../src/constants';
import { Public, META_PUBLIC } from '../../src/decorators/public.decorator';
import { Resource, META_RESOURCE } from '../../src/decorators/resource.decorator';
import { KeycloakEnforcerOptions } from '../../src/interface/enforcer-options.interface';
import { EnforcerOptions, META_ENFORCER_OPTIONS } from '../../src/decorators/enforcer-options.decorator';
import { META_ROLES, META_ROLE_MATCHING_MODE, RoleMatchingMode, Roles } from '../../src/decorators/roles.decorator';
import {
   ConditionalScopes,
   META_CONDITIONAL_SCOPES,
   META_SCOPES,
   Scopes,
} from '../../src/decorators/scopes.decorator';

describe('metadata decorators', () => {
   it('sets public metadata', () => {
      class ControllerClass {}
      Public()(ControllerClass);
      expect(Reflect.getMetadata(META_PUBLIC, ControllerClass)).toBe(true);
   });

   it('sets resource metadata', () => {
      class ControllerClass {}
      Resource('orders')(ControllerClass);
      expect(Reflect.getMetadata(META_RESOURCE, ControllerClass)).toBe('orders');
   });

   it('sets roles and role matching metadata', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      Roles('admin', 'realm:sysadmin')(
         ControllerClass.prototype,
         'method',
         descriptor,
      );
      RoleMatchingMode(RoleMatch.ALL)(
         ControllerClass.prototype,
         'method',
         descriptor,
      );

      expect(
         Reflect.getMetadata(META_ROLES, ControllerClass.prototype.method),
      ).toEqual(['admin', 'realm:sysadmin']);
      expect(
         Reflect.getMetadata(META_ROLE_MATCHING_MODE, ControllerClass.prototype.method),
      ).toBe(RoleMatch.ALL);
   });

   it('sets roles metadata from a single string', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      Roles('admin')(ControllerClass.prototype, 'method', descriptor);

      expect(
         Reflect.getMetadata(META_ROLES, ControllerClass.prototype.method),
      ).toEqual(['admin']);
   });

   it('sets roles metadata from an array of strings', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      Roles(['admin', 'basic'])(ControllerClass.prototype, 'method', descriptor);

      expect(
         Reflect.getMetadata(META_ROLES, ControllerClass.prototype.method),
      ).toEqual(['admin', 'basic']);
   });

   it('sets roles metadata from an object with roles array', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      Roles({ roles: ['realm:admin', 'realm:basic'] })(
         ControllerClass.prototype,
         'method',
         descriptor,
      );

      expect(
         Reflect.getMetadata(META_ROLES, ControllerClass.prototype.method),
      ).toEqual(['realm:admin', 'realm:basic']);
   });

   it('sets empty roles metadata when called with no arguments', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      Roles()(ControllerClass.prototype, 'method', descriptor);

      expect(
         Reflect.getMetadata(META_ROLES, ControllerClass.prototype.method),
      ).toEqual([]);
   });

   it('sets scopes and conditional scopes metadata', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      const resolver = jest.fn(() => ['x']);
      Scopes('read', 'write')(ControllerClass.prototype, 'method', descriptor);
      ConditionalScopes(resolver)(ControllerClass.prototype, 'method', descriptor);

      expect(
         Reflect.getMetadata(META_SCOPES, ControllerClass.prototype.method),
      ).toEqual(['read', 'write']);
      expect(
         Reflect.getMetadata(
            META_CONDITIONAL_SCOPES,
            ControllerClass.prototype.method,
         ),
      ).toBe(resolver);
   });

   it('sets enforcer options metadata', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;
      const opts = { response_mode: 'permissions' } as KeycloakEnforcerOptions;
      EnforcerOptions(opts)(ControllerClass.prototype, 'method', descriptor);

      expect(
         Reflect.getMetadata(META_ENFORCER_OPTIONS, ControllerClass.prototype.method),
      ).toBe(opts);
   });
});
