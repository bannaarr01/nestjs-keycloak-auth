import { KeycloakAdminError } from '../errors';
import { KeycloakAdminService } from '../services/keycloak-admin.service';
import { ServerRequest, ServerResponse } from '../interface/server.interface';
import {
   Body,
   Controller,
   HttpCode,
   Logger,
   Post,
   Req,
   Res,
} from '@nestjs/common';

/**
 * Handles Keycloak admin callbacks:
 * - `POST k_push_not_before`: not-before policy updates
 * - `POST k_logout`: OIDC back-channel logout tokens
 *
 * All business logic is delegated to {@link KeycloakAdminService}.
 */
@Controller()
export class KeycloakAdminController {
   private readonly logger = new Logger(KeycloakAdminController.name);

   constructor(private readonly adminService: KeycloakAdminService) {}

  @Post('k_push_not_before')
  @HttpCode(200)
   async handlePushNotBefore(
    @Body() body: unknown,
    @Req() request: ServerRequest,
    @Res() response: ServerResponse,
   ) {
      try {
         await this.adminService.processPushNotBefore(body, request);
         response.send('ok');
      } catch (err) {
         this.logger.warn(`Push not-before failed: ${err}`);
         const status = err instanceof KeycloakAdminError ? 401 : 400;
         response.status(status).end(status === 401 ? 'unauthorized' : 'bad request');
      }
   }

  @Post('k_logout')
  @HttpCode(200)
  async handleBackchannelLogout(
    @Body() body: unknown,
    @Req() request: ServerRequest,
    @Res() response: ServerResponse,
  ) {
     try {
        await this.adminService.processBackchannelLogout(body, request);
        response.send('ok');
     } catch (err) {
        this.logger.warn(`Back-channel logout failed: ${err}`);
        const status = err instanceof KeycloakAdminError ? 401 : 400;
        response.status(status).end(status === 401 ? 'unauthorized' : 'bad request');
     }
  }
}
