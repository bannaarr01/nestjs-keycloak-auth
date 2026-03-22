import { Product } from './product';
import { Injectable, Logger } from '@nestjs/common';
import { HeaderValue } from '../../types/header-value.type';
import { ExampleUser } from '../../interface/example-user.interface';
import { ProductRequest } from '../../interface/product-request.interface';

const getHeaderValue = (
  headers: Record<string, HeaderValue> | undefined,
  key: string,
): string | undefined => {
  const headerValue = headers?.[key];
  if (typeof headerValue === 'string') {
    const normalized = headerValue.trim();
    return normalized.length > 0 ? normalized : undefined;
  }
  if (Array.isArray(headerValue) && headerValue.length > 0) {
    const first = headerValue[0]?.trim();
    return first && first.length > 0 ? first : undefined;
  }
  return undefined;
};

export const buildTenantClaims = (request: unknown): Record<string, unknown> => {
  const req = request as ProductRequest;
  return {
    tenant: getHeaderValue(req.headers, 'x-tenant-realm') ?? 'nest-example',
    api: 'nestjs-keycloak-auth-example',
  };
};

@Injectable()
export class ProductService {
  private readonly logger = new Logger(ProductService.name);

  products: Product[] = [
    {
      code: '1-00-1',
    },
    {
      code: '1-00-2',
    },
    {
      code: '1-00-3',
    },
  ];

  findAllByScopes(scopes: string[]) {
    if (scopes.includes('View.All')) {
      return this.findAll();
    }
    return this.findByCode('1-00-1');
  }

  permissionsMode(
    request: ProductRequest,
    scopes: string[],
    user: ExampleUser | undefined,
  ) {
    return {
      mode: 'permissions',
      scopes,
      username: user?.preferred_username ?? null,
      serverPermissions: request.permissions ?? [],
      products: this.findAll(),
    };
  }

  tokenMode(
    code: string,
    accessToken: string | undefined,
  ) {
    return {
      mode: 'token',
      code,
      product: this.findByCode(code),
      tokenPreview: accessToken ? `${accessToken.slice(0, 16)}...` : null,
    };
  }

  decisionMode(
    tenantRealm: string | undefined,
    scopes: string[],
  ) {
    return {
      mode: 'decision',
      scopes,
      tenantRealm: tenantRealm ?? null,
      totalProducts: this.findAll().length,
    };
  }

  findByCodeWithUser(
    code: string,
    user: ExampleUser | undefined,
  ) {
    this.logger.log(`findByCode requested by ${user?.preferred_username ?? 'unknown-user'}`);
    return {
      product: this.findByCode(code),
      requestedBy: user?.preferred_username ?? null,
    };
  }

  update(code: string, product: Product) {
    this.products = this.products.map((p) => {
      if (p.code === code) {
        return product;
      } else {
        return p;
      }
    });
  }

  deleteByCode(code: string) {
    this.products = this.products.filter((p) => p.code !== code);
  }

  create(product: Product) {
    this.products = [...this.products, product];
  }

  findByCode(code: string) {
    return this.products.find((p) => p.code === code);
  }

  findAll() {
    return this.products;
  }
}
