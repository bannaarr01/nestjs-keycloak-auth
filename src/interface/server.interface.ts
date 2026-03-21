export interface ServerResponse {
  status(code: number): ServerResponse;
  end(data?: string): void;
  send(data: string): void;
}

export interface ServerRequest {
  body?: unknown;
  rawBody?: unknown;
  [key: string]: unknown;
}
