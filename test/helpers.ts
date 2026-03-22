import { ExecutionContext } from '@nestjs/common';
import {
   KeycloakAuthConfig,
   MultiTenantOptions,
} from '../src/interface/keycloak-auth-options.interface';

export const b64 = (value: unknown): string =>
   Buffer.from(JSON.stringify(value)).toString('base64');

export const makeJwt = (
   payload: Record<string, unknown>,
   header: Record<string, unknown> = { alg: 'RS256', typ: 'Bearer', kid: 'kid-1' },
   signature: string = Buffer.from('sig').toString('base64'),
): string => `${b64(header)}.${b64(payload)}.${signature}`;

export const makeContext = (
   request: unknown,
   response: unknown = {},
): ExecutionContext =>
   ({
      getType: () => 'http',
      switchToHttp: () => ({
         getRequest: () => request,
         getResponse: () => response,
      }),
      getClass: () => class TestClass {},
      getHandler: () => function testHandler() {},
   }) as unknown as ExecutionContext;

type TestMultiTenantOptions = Omit<
   Partial<MultiTenantOptions>,
   'realmResolver' | 'realmClientIdResolver'
> & {
   realmResolver?: MultiTenantOptions['realmResolver'];
   realmClientIdResolver?: MultiTenantOptions['realmClientIdResolver'];
};

export type TestKeycloakConfig = Omit<Partial<KeycloakAuthConfig>, 'multiTenant'> & {
   multiTenant?: TestMultiTenantOptions;
};

export const asKeycloakConfig = (
   config: TestKeycloakConfig = {},
): KeycloakAuthConfig => config as unknown as KeycloakAuthConfig;

export const asService = <T>(service: unknown): T => service as T;

export const getPrivate = <T>(instance: object, key: string): T =>
   Reflect.get(instance, key) as T;

export const callPrivate = <TArgs extends unknown[], TResult>(
   instance: object,
   key: string,
   ...args: TArgs
): TResult => {
   const method = getPrivate<(...callArgs: TArgs) => TResult>(instance, key);
   return method.apply(instance, args);
};
