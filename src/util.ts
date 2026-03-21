export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  preferred_username?: string;
  [key: string]: unknown;
}

export const parseToken = (token: string): JwtPayload => {
  const parts = token.split('.');
  return JSON.parse(Buffer.from(parts[1], 'base64').toString()) as JwtPayload;
};
