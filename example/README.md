## Example application for nestjs-keycloak-auth

A [realm configuration](nest-example.json) is provided to get you up and running in Keycloak immediately.

This example demonstrates bearer-token API usage with NestJS guards. It does not include browser session/login redirect flows.
It includes callback endpoints for `POST /k_push_not_before` and `POST /k_logout` used by Keycloak admin/back-channel events.

## Installation
```bash
$ cd ../
$ npm run build
$ cd example
$ npm install
```

## Running the app

```bash
# development
$ npm run start
```
