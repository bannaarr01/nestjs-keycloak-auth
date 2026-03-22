import { asService } from '../helpers';
import { KeycloakAdminError } from '../../src/errors';
import { KeycloakAdminService } from '../../src/services/keycloak-admin.service';
import { ServerRequest, ServerResponse } from '../../src/interface/server.interface';
import { KeycloakAdminController } from '../../src/controllers/keycloak-admin.controller';

type TestResponse = ServerResponse & {
   code?: number;
   data?: unknown;
   status: jest.Mock;
   send: jest.Mock;
};

type MockAdminService = {
   processPushNotBefore: jest.Mock;
   processBackchannelLogout: jest.Mock;
};

const makeResponse = (): TestResponse => {
   const response: TestResponse = {
      code: undefined,
      data: undefined,
      status: jest.fn(),
      send: jest.fn(),
   } as unknown as TestResponse;

   response.status.mockImplementation((code: number) => {
      response.code = code;
      return response;
   });
   response.send.mockImplementation((data: unknown) => {
      response.data = data;
   });

   return response;
};

describe('KeycloakAdminController', () => {
   const buildController = () => {
      const adminService: MockAdminService = {
         processPushNotBefore: jest.fn(),
         processBackchannelLogout: jest.fn(),
      };
      const controller = new KeycloakAdminController(
         asService<KeycloakAdminService>(adminService),
      );

      return { controller, adminService };
   };

   it('handles successful push-not-before callback', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();

      await controller.handlePushNotBefore('token', {} as ServerRequest, response);

      expect(adminService.processPushNotBefore).toHaveBeenCalledWith('token', {});
      expect(response.send).toHaveBeenCalledWith('ok');
   });

   it('returns 401 for push-not-before admin auth errors', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processPushNotBefore.mockRejectedValueOnce(
         new KeycloakAdminError('bad signature'),
      );

      await controller.handlePushNotBefore('token', {} as ServerRequest, response);

      expect(response.status).toHaveBeenCalledWith(401);
      expect(response.send).toHaveBeenCalledWith('unauthorized');
   });

   it('returns 400 for push-not-before non-admin errors', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processPushNotBefore.mockRejectedValueOnce(new Error('bad payload'));

      await controller.handlePushNotBefore('token', {} as ServerRequest, response);

      expect(response.status).toHaveBeenCalledWith(400);
      expect(response.send).toHaveBeenCalledWith('bad request');
   });

   it('returns 400 with generic message for non-Error push-not-before failures', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processPushNotBefore.mockRejectedValueOnce('boom');

      await controller.handlePushNotBefore('token', {} as ServerRequest, response);

      expect(response.status).toHaveBeenCalledWith(400);
      expect(response.send).toHaveBeenCalledWith('bad request');
   });

   it('handles successful back-channel logout callback', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();

      await controller.handleBackchannelLogout(
         { logout_token: 'token' },
         {} as ServerRequest,
         response,
      );

      expect(adminService.processBackchannelLogout).toHaveBeenCalledWith(
         { logout_token: 'token' },
         {},
      );
      expect(response.send).toHaveBeenCalledWith('ok');
   });

   it('returns 401 for back-channel admin auth errors', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processBackchannelLogout.mockRejectedValueOnce(
         new KeycloakAdminError('bad signature'),
      );

      await controller.handleBackchannelLogout(
         { logout_token: 'token' },
         {} as ServerRequest,
         response,
      );

      expect(response.status).toHaveBeenCalledWith(401);
      expect(response.send).toHaveBeenCalledWith('unauthorized');
   });

   it('returns 400 for back-channel non-admin errors', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processBackchannelLogout.mockRejectedValueOnce(
         new Error('bad payload'),
      );

      await controller.handleBackchannelLogout(
         { logout_token: 'token' },
         {} as ServerRequest,
         response,
      );

      expect(response.status).toHaveBeenCalledWith(400);
      expect(response.send).toHaveBeenCalledWith('bad request');
   });

   it('returns 400 with generic message for non-Error back-channel failures', async () => {
      const { controller, adminService } = buildController();
      const response = makeResponse();
      adminService.processBackchannelLogout.mockRejectedValueOnce('boom');

      await controller.handleBackchannelLogout(
         { logout_token: 'token' },
         {} as ServerRequest,
         response,
      );

      expect(response.status).toHaveBeenCalledWith(400);
      expect(response.send).toHaveBeenCalledWith('bad request');
   });
});
