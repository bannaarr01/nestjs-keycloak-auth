import { makeContext } from '../helpers';

type ParamDecoratorFactory = (data: unknown, ctx: ReturnType<typeof makeContext>) => unknown;

const passthroughDecoratorFactory = (factory: ParamDecoratorFactory): ParamDecoratorFactory =>
   factory;

describe('param decorators', () => {
   afterEach(() => {
      jest.resetModules();
      jest.clearAllMocks();
   });

   it('AccessToken returns request accessToken', async () => {
      jest.doMock('@nestjs/common', () => {
         const actual = jest.requireActual('@nestjs/common');
         return {
            ...actual,
            createParamDecorator: passthroughDecoratorFactory,
         };
      });

      const mod = await import('../../src/decorators/access-token.decorator');
      const context = makeContext({ accessToken: 'jwt-1' });

      expect((mod.AccessToken as unknown as ParamDecoratorFactory)(undefined, context)).toBe(
         'jwt-1',
      );
   });

   it('KeycloakUser returns request user', async () => {
      jest.doMock('@nestjs/common', () => {
         const actual = jest.requireActual('@nestjs/common');
         return {
            ...actual,
            createParamDecorator: passthroughDecoratorFactory,
         };
      });

      const mod = await import('../../src/decorators/keycloak-user.decorator');
      const context = makeContext({ user: { sub: 'u1' } });

      expect((mod.KeycloakUser as unknown as ParamDecoratorFactory)(undefined, context)).toEqual({
         sub: 'u1',
      });
   });

   it('ResolvedScopes returns request scopes', async () => {
      jest.doMock('@nestjs/common', () => {
         const actual = jest.requireActual('@nestjs/common');
         return {
            ...actual,
            createParamDecorator: passthroughDecoratorFactory,
         };
      });

      const mod = await import('../../src/decorators/scopes.decorator');
      const context = makeContext({ scopes: ['a', 'b'] });

      expect((mod.ResolvedScopes as unknown as ParamDecoratorFactory)(undefined, context)).toEqual(
         ['a', 'b'],
      );
   });
});
