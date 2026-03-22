export interface JwksKey {
  kid: string;
  kty: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
}

export interface JwksResponse {
  keys: JwksKey[];
}

export interface CachedJwks {
  keys: Map<string, JwksKey>;
  fetchedAt: number;
}
