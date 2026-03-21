import { JwtPayload } from './interface/jwt.interface';

export { JwtPayload };

export const parseToken = (token: string): JwtPayload => {
  const parts = token.split('.');
  return JSON.parse(Buffer.from(parts[1], 'base64').toString()) as JwtPayload;
};
