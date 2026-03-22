import { KeycloakTokenError } from './errors';
import { JwtPayload } from './interface/jwt.interface';

export { JwtPayload };

export const parseToken = (token: string): JwtPayload => {
   const parts = token.split('.');
   if (parts.length < 2) {
      throw new KeycloakTokenError('Malformed JWT: expected at least 2 segments');
   }
   try {
      return JSON.parse(Buffer.from(parts[1], 'base64').toString()) as JwtPayload;
   } catch {
      throw new KeycloakTokenError('Malformed JWT: payload is not valid JSON');
   }
};
