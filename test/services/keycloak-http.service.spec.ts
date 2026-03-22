import { of, throwError } from 'rxjs';
import { asService } from '../helpers';
import { HttpService } from '@nestjs/axios';
import { KeycloakHttpService } from '../../src/services/keycloak-http.service';
import { OidcDiscoveryService } from '../../src/services/oidc-discovery.service';

type MockHttpService = {
   request: jest.Mock;
};

type MockOidcDiscoveryService = {
   getEndpoints: jest.Mock;
};

describe('KeycloakHttpService', () => {
   const endpoints = {
      jwks_uri: 'https://kc/jwks',
      token_endpoint: 'https://kc/token',
      introspection_endpoint: 'https://kc/introspect',
      userinfo_endpoint: 'https://kc/userinfo',
   };

   const setup = () => {
      const httpService: MockHttpService = { request: jest.fn() };
      const oidcDiscovery: MockOidcDiscoveryService = {
         getEndpoints: jest.fn().mockResolvedValue(endpoints),
      };
      const service = new KeycloakHttpService(
         asService<HttpService>(httpService),
         asService<OidcDiscoveryService>(oidcDiscovery),
      );
      return { service, httpService, oidcDiscovery };
   };

   it('fetches jwks', async () => {
      const { service, httpService, oidcDiscovery } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { keys: [] } }));

      const res = await service.fetchJwks('realm');

      expect(oidcDiscovery.getEndpoints).toHaveBeenCalledWith('realm');
      expect(httpService.request).toHaveBeenCalledWith(
         expect.objectContaining({
            url: endpoints.jwks_uri,
            method: 'GET',
         }),
      );
      expect(res).toEqual({ keys: [] });
   });

   it('introspects token', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { active: true } }));

      const res = await service.introspectToken('realm', 'client', 'secret', 'jwt');
      const arg = httpService.request.mock.calls[0][0];

      expect(arg.url).toBe(endpoints.introspection_endpoint);
      expect(arg.method).toBe('POST');
      expect(arg.data).toContain('client_id=client');
      expect(arg.data).toContain('client_secret=secret');
      expect(arg.data).toContain('token=jwt');
      expect(res).toEqual({ active: true });
   });

   it('obtains client credentials grant for confidential and public clients', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValue(of({ data: { access_token: 'a' } }));

      await service.obtainClientCredentialsGrant(
         'realm',
         'client',
         'secret',
         undefined,
         false,
      );
      const confidentialReq = httpService.request.mock.calls[0][0];
      expect(confidentialReq.url).toBe(endpoints.token_endpoint);
      expect(confidentialReq.data).toContain('grant_type=client_credentials');
      expect(confidentialReq.data).toContain('scope=openid');
      expect(confidentialReq.headers.Authorization).toContain('Basic ');

      await service.obtainClientCredentialsGrant(
         'realm',
         'client',
         'secret',
         'email',
         true,
      );
      const publicReq = httpService.request.mock.calls[1][0];
      expect(publicReq.data).toContain('scope=email');
      expect(publicReq.headers.Authorization).toBeUndefined();
   });

   it('uses default isPublic=false when omitted in client credentials grant', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { access_token: 'a' } }));

      await service.obtainClientCredentialsGrant('realm', 'client', 'secret', 'openid');
      const req = httpService.request.mock.calls[0][0];
      expect(req.headers.Authorization).toContain('Basic ');
   });

   it('fetches user info', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { sub: 'u1' } }));

      const res = await service.getUserInfo('realm', 'at');
      const arg = httpService.request.mock.calls[0][0];

      expect(arg.url).toBe(endpoints.userinfo_endpoint);
      expect(arg.headers.Authorization).toBe('Bearer at');
      expect(res).toEqual({ sub: 'u1' });
   });

   it('checks permission in decision mode with claims and confidential subject_token', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { result: true } }));

      const res = await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         {
            claims: { tenant: 'a' },
            response_mode: 'decision',
            audience: 'api',
            isPublic: false,
         },
      );
      const arg = httpService.request.mock.calls[0][0];

      expect(res).toBe(true);
      expect(arg.url).toBe(endpoints.token_endpoint);
      expect(arg.data).toContain('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket');
      expect(arg.data).toContain('audience=api');
      expect(arg.data).toContain('response_mode=decision');
      expect(arg.data).toContain('permission=orders%3Aview');
      expect(arg.data).toContain('claim_token=');
      expect(arg.data).toContain('claim_token_format=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt');
      expect(arg.data).toContain('subject_token=at');
      expect(arg.headers.Authorization).toContain('Basic ');
   });

   it('checks permission in permissions mode', async () => {
      const { service, httpService } = setup();
      const permissions = [{ rsid: 'orders', scopes: ['view'] }];
      httpService.request.mockReturnValueOnce(of({ data: permissions }));

      const res = await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         { response_mode: 'permissions' },
      );
      const arg = httpService.request.mock.calls[0][0];

      expect(arg.data).toContain('response_mode=permissions');
      expect(res).toEqual(permissions);
   });

   it('checks permission in token mode with public client + explicit subject token', async () => {
      const { service, httpService } = setup();
      const tokenResponse = { access_token: 'new-at' };
      httpService.request.mockReturnValueOnce(of({ data: tokenResponse }));

      const res = await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         {
            response_mode: 'token',
            isPublic: true,
            subject_token: 'subject',
         },
      );
      const arg = httpService.request.mock.calls[0][0];

      expect(arg.data).not.toContain('response_mode=');
      expect(arg.data).toContain('subject_token=subject');
      expect(arg.headers.Authorization).toBe('Bearer at');
      expect(res).toEqual(tokenResponse);
   });

   it('returns false on decision mode error', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(throwError(() => new Error('boom')));

      const res = await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         { response_mode: 'decision' },
      );
      expect(res).toBe(false);
   });

   it('uses default decision mode and default audience when options are omitted', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { result: false } }));

      const res = await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
      );
      const arg = httpService.request.mock.calls[0][0];

      expect(res).toBe(false);
      expect(arg.data).toContain('response_mode=decision');
      expect(arg.data).toContain('audience=client');
   });

   it('throws on non-decision mode error', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(throwError(() => new Error('boom')));

      await expect(
         service.checkPermission(
            'realm',
            'client',
            'secret',
            'at',
            ['orders:view'],
            { response_mode: 'permissions' },
         ),
      ).rejects.toThrow('Permission check failed');
   });

   it('sets subject_token from access token for confidential clients when subject_token is omitted', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { access_token: 'x' } }));

      await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         { response_mode: 'token', isPublic: false },
      );
      const req = httpService.request.mock.calls[0][0];
      expect(req.data).toContain('subject_token=at');
      expect(req.headers.Authorization).toContain('Basic ');
   });

   it('does not set subject_token when client is public and subject_token is omitted', async () => {
      const { service, httpService } = setup();
      httpService.request.mockReturnValueOnce(of({ data: { access_token: 'x' } }));

      await service.checkPermission(
         'realm',
         'client',
         'secret',
         'at',
         ['orders:view'],
         { response_mode: 'token', isPublic: true },
      );
      const req = httpService.request.mock.calls[0][0];
      expect(req.data).not.toContain('subject_token=');
      expect(req.headers.Authorization).toBe('Bearer at');
   });
});
