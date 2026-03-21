import { firstValueFrom } from 'rxjs';
import { randomUUID } from 'node:crypto';
import { HttpService } from '@nestjs/axios';
import { RequestOptions } from './types/request.types';
import { AxiosError, AxiosRequestConfig, AxiosResponse } from 'axios';
import { ProxyConfigService } from './proxy-config.service';
import { ProxyServiceConfig } from './interfaces/proxy-config.interface';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ProxyService {
  private readonly logger = new Logger(ProxyService.name);

  constructor(
    private readonly httpService: HttpService,
    private readonly proxyConfigService: ProxyConfigService,
  ) {}

  async executeRequest<T = unknown>(
    serviceName: string,
    endpointName: string,
    method: string,
    options: RequestOptions = {},
    overrideBaseUrl?: string,
  ): Promise<T> {
    try {
      const serviceConfig =
        this.proxyConfigService.getServiceConfig(serviceName);
      if (!serviceConfig) {
        throw new HttpException(
          `Service '${serviceName}' not configured`,
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }

      const endpointConfig = serviceConfig.endpoints[endpointName];
      if (!endpointConfig) {
        throw new HttpException(
          `Endpoint '${endpointName}' not configured for service '${serviceName}'`,
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      }

      const resolvedBaseUrl = overrideBaseUrl || serviceConfig.baseUrl;
      const url = this.buildUrl(
        resolvedBaseUrl,
        endpointConfig.targetEndpoint,
        options.params || {},
      );
      const timeoutMs =
        endpointConfig.timeoutMs || serviceConfig.timeoutMs || 30000;
      const headers = {
        ...(serviceConfig.headers || {}),
        ...(endpointConfig.headers || {}),
        ...(options.headers || {}),
      };

      const config: AxiosRequestConfig = {
        method: method.toLowerCase() as NonNullable<
          AxiosRequestConfig['method']
        >,
        url,
        timeout: timeoutMs,
        params: options.query || {},
        headers,
        maxRedirects: 0,
      };

      const methodUpper = method.toUpperCase();
      if (
        !['GET', 'DELETE'].includes(methodUpper) &&
        options.data !== undefined
      ) {
        config.data = options.data;
      }

      const response = (await firstValueFrom(
        this.httpService.request<T>(config),
      )) as AxiosResponse<T>;
      return response.data;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      this.logger.error((error as Error)?.message || 'Proxy request failed');
      const status =
        (error as AxiosError)?.response?.status || HttpStatus.BAD_GATEWAY;
      throw new HttpException(
        (error as Error)?.message || 'Proxy request failed',
        status,
      );
    }
  }

  async executeDynamicRequest<T = unknown>(
    config: ProxyServiceConfig,
    endpointName: string,
    method: string,
    options: RequestOptions = {},
  ): Promise<T> {
    const tempName = `__dynamic_service__${randomUUID()}`;
    this.proxyConfigService.setServiceConfig(tempName, config);

    try {
      return await this.executeRequest<T>(
        tempName,
        endpointName,
        method,
        options,
      );
    } finally {
      this.proxyConfigService.removeServiceConfig(tempName);
    }
  }

  private buildUrl(
    baseUrl: string,
    endpoint: string,
    params: Record<string, string | number>,
  ): string {
    const validatedBaseUrl = this.validateBaseUrl(baseUrl);
    let url = `${validatedBaseUrl.replace(/\/$/, '')}/${endpoint.replace(/^\//, '')}`;

    Object.entries(params).forEach(([key, value]) => {
      url = url.replace(`{${key}}`, encodeURIComponent(String(value)));
    });

    return url;
  }

  private validateBaseUrl(baseUrl: string): string {
    let parsedUrl: URL;

    try {
      parsedUrl = new URL(baseUrl);
    } catch {
      throw new HttpException(
        `Invalid proxy base URL: ${baseUrl}`,
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      throw new HttpException(
        'Proxy base URL must use http or https',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (parsedUrl.username || parsedUrl.password) {
      throw new HttpException(
        'Proxy base URL must not contain credentials',
        HttpStatus.BAD_REQUEST,
      );
    }

    return parsedUrl.toString().replace(/\/$/, '');
  }
}
