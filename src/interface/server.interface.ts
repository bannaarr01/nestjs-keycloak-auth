export interface ServerResponse {
  status(code: number): ServerResponse;
  send(data: string): void;
}

export interface ServerRequest {
  body?: unknown;
  rawBody?: unknown;
  [key: string]: unknown;
}
