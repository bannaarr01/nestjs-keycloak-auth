import 'reflect-metadata';
import { META_TOKEN_SCOPES, TokenScopes } from '../../src/decorators/token-scopes.decorator';

describe('TokenScopes decorator', () => {
   it('sets token scope metadata', () => {
      class ControllerClass {
         method(): void {}
      }
      const descriptor = Object.getOwnPropertyDescriptor(
         ControllerClass.prototype,
         'method',
      ) as PropertyDescriptor;

      TokenScopes('openid', 'profile')(
         ControllerClass.prototype,
         'method',
         descriptor,
      );

      expect(
         Reflect.getMetadata(META_TOKEN_SCOPES, ControllerClass.prototype.method),
      ).toEqual(['openid', 'profile']);
   });
});
