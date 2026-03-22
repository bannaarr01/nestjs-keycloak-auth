/**
 * Base error class for all nestjs-keycloak-auth errors.
 * Consumers can catch `instanceof KeycloakAuthError` to handle any library error.
 */
export class KeycloakAuthError extends Error {
   readonly code: string;

   constructor(message: string, code: string = 'KEYCLOAK_AUTH_ERROR') {
      super(message);
      this.name = this.constructor.name;
      this.code = code;
      Object.setPrototypeOf(this, new.target.prototype);
   }
}

/** Configuration invariants, missing values, file not found. */
export class KeycloakConfigError extends KeycloakAuthError {
   constructor(message: string) {
      super(message, 'KEYCLOAK_CONFIG_ERROR');
   }
}

/** Token parsing, grant validation, JWKS key not found. */
export class KeycloakTokenError extends KeycloakAuthError {
   constructor(message: string) {
      super(message, 'KEYCLOAK_TOKEN_ERROR');
   }
}

/** Permission check failures. */
export class KeycloakPermissionError extends KeycloakAuthError {
   constructor(message: string) {
      super(message, 'KEYCLOAK_PERMISSION_ERROR');
   }
}

/** Admin callback signature verification, invalid admin tokens. */
export class KeycloakAdminError extends KeycloakAuthError {
   constructor(message: string) {
      super(message, 'KEYCLOAK_ADMIN_ERROR');
   }
}
