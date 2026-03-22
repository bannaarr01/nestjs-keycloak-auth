import { makeJwt } from './helpers';
import { parseToken } from '../src/util';

describe('parseToken', () => {
   it('parses JWT payload', () => {
      const payload = { sub: 'user-1', iss: 'https://kc/realms/a', exp: 9999999999 };
      const token = makeJwt(payload);

      expect(parseToken(token)).toEqual(payload);
   });

   it('throws for malformed JWT payload JSON', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256' })).toString('base64');
      const invalidPayload = Buffer.from('{invalid').toString('base64');
      const token = `${header}.${invalidPayload}.sig`;

      expect(() => parseToken(token)).toThrow('Malformed JWT: payload is not valid JSON');
   });
});
