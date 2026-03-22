## nestjs-keycloak-auth Example

This example is a bearer-only API demo that exercises the major features of `nestjs-keycloak-auth`:

- `AuthGuard`, `ResourceGuard`, `RoleGuard` as global guards
- `@Public`, `@Roles`, `@RoleMatchingMode`
- `@TokenScopes` (OAuth scope checks from token `scope` claim)
- `@Resource`, `@Scopes`, `@ConditionalScopes`, `@ResolvedScopes`
- `@EnforcerOptions` with `decision`, `permissions`, and `token` response modes
- `@KeycloakUser` and `@AccessToken`
- OFFLINE validation + audience verification
- Multi-tenant realm/client/secret/auth-server resolvers
- Built-in admin callbacks: `POST /k_push_not_before` and `POST /k_logout`

`k_push_not_before` and `k_logout` are callback endpoints for Keycloak-to-API communication, not browser session flows.

For full Keycloak configuration steps (including callbacks and multi-tenant), see [dev/guide.md](../dev/guide.md).

## Included Realm Export

Compose imports these realm files from [`realm-export/`](./realm-export/):

- `nest-example-realm.json`
- `tenant-a-realm.json`
- `tenant-b-realm.json`

`master-realm.json` is kept for backup/reference only and is not auto-imported on startup.
This avoids a duplicate `admin` user conflict with bootstrap admin creation.

Default sample users in this realm export:

- `user` / `user` (has basic roles for product routes)
- `admin` / `admin` (useful for admin-only route testing after role assignment)

## Install

```bash
npm install
```

## Run

```bash
npm run start:dev
```

Or run full stack (API + Keycloak + DB) via compose:

```bash
npm run kc:up
```

If you only want Keycloak+DB in Docker and keep API on host:

```bash
npm run kc:up:keycloak
```

## Docker Compose Stack

Use the included compose file:

```bash
cd example
npm run kc:up
```

What this does:

- Builds and starts example API on `http://localhost:3000`
- Starts pinned Keycloak (`quay.io/keycloak/keycloak:26.5.6`) on `http://localhost:8080`
- Starts Postgres for Keycloak storage
- Uses bootstrap admin credentials `admin` / `admin`
- Auto-imports `nest-example`, `tenant-a`, and `tenant-b` realm files only

## Generate a Fresh Realm Export (Latest Keycloak Format)

After you modify/create realm config in Keycloak UI, export with:

```bash
cd example
docker compose stop keycloak
docker compose run --rm keycloak export --dir /opt/keycloak/data/export --realm nest-example --users realm_file
docker compose up -d keycloak
```

Exported files will be written to `example/realm-export/`.

## Optional Environment Variables

The example works without env vars, but supports overrides:

- `KC_AUTH_SERVER_URL` (default: `http://localhost:8080`)
- `KC_REALM` (default: `nest-example`)
- `KC_CLIENT_ID` (default: `nest-api`)
- `KC_CLIENT_SECRET` (default: sample secret from realm export)
- `KC_TOKEN_VALIDATION` (`offline` | `online` | `none`, default: `offline`)
- `KC_POLICY_ENFORCEMENT` (`permissive` | `enforcing`, default: `permissive`)
- `KC_TENANT_A_*`, `KC_TENANT_B_*` overrides for tenant-specific resolver values

## Multi-tenant Demo

Send `x-tenant-realm` header to force tenant resolution:

```bash
curl -H "x-tenant-realm: tenant-a" http://localhost:3000/tenant
```

If header is absent, resolver falls back to host-derived realm and then configured default realm.

## Endpoint Map

Public routes:

- `GET /` public hello + callback path hints
- `GET /tenant` public tenant header echo

Auth + token-scope routes:

- `GET /private` requires auth + `openid` scope
- `GET /me` requires auth + `openid profile` scopes

Role routes:

- `GET /roles/any` `realm:basic OR basic`
- `GET /roles/all` `realm:basic AND basic`
- `GET /roles/admin` `realm:admin`

Product resource routes (`@Resource(Product)`):

- `GET /product` conditional scopes (`View` / `View.All`)
- `GET /product/:code` role-protected lookup
- `POST /product` scope `Create` + token scope `openid`
- `PUT /product/:code` scope `Edit` + token scope `openid`
- `DELETE /product/:code` scope `Delete` + token scope `openid`

UMA response-mode demo routes:

- `GET /product/uma/permissions` (`response_mode: permissions`)
- `GET /product/uma/token/:code` (`response_mode: token`)
- `GET /product/uma/decision` (`response_mode: decision`)

Admin callback routes mounted by library:

- `POST /k_push_not_before`
- `POST /k_logout`

These are verified with Keycloak signatures and update in-memory revocation state.

## Token Request Example

```bash
curl --request POST \
  --url http://localhost:8080/realms/nest-example/protocol/openid-connect/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=password' \
  --data 'client_id=postman' \
  --data 'username=user' \
  --data 'password=user' \
  --data 'scope=openid profile email'
```
