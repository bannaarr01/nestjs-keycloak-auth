import { Injectable } from '@nestjs/common';
import { ProxyServiceConfig } from './interfaces/proxy-config.interface';

@Injectable()
export class ProxyConfigService {
  private readonly configs: Record<string, ProxyServiceConfig> = {};

  getProxyConfigurations(): Record<string, ProxyServiceConfig> {
    return this.configs;
  }

  getServiceConfig(serviceName: string): ProxyServiceConfig | undefined {
    return this.configs[serviceName];
  }

  setServiceConfig(serviceName: string, config: ProxyServiceConfig): void {
    this.configs[serviceName] = config;
  }

  removeServiceConfig(serviceName: string): void {
    delete this.configs[serviceName];
  }
}
