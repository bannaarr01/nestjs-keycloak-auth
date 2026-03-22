import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AppService } from './app.service';
import { AppController } from './app.controller';
import { ConfigModule } from './config/config.module';
import { ProductModule } from './product/product.module';
import { KeycloakConfigService } from './config/keycloak-config.service';
import { AuthGuard, KeycloakAuthModule, ResourceGuard, RoleGuard } from 'nestjs-keycloak-auth';

@Module({
  imports: [
    KeycloakAuthModule.registerAsync({
      useExisting: KeycloakConfigService,
      imports: [ConfigModule],
    }),
    ProductModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ResourceGuard,
    },
    {
      provide: APP_GUARD,
      useClass: RoleGuard,
    },
    AppService,
  ],
  controllers: [AppController],
})
export class AppModule {}
