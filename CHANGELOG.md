# Changelog

## [1.0.4](https://github.com/bannaarr01/nestjs-keycloak-auth/compare/v1.0.3...v1.0.4) (2026-04-04)


### Bug Fixes

* cap axios below 1.14.0 to mitigate supply chain compromise ([4da5ee6](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/4da5ee69f42f85e0358893643479e0a959f37b18))

## [1.0.3](https://github.com/bannaarr01/nestjs-keycloak-auth/compare/v1.0.2...v1.0.3) (2026-04-01)

## [1.0.2](https://github.com/bannaarr01/nestjs-keycloak-auth/compare/v1.0.1...v1.0.2) (2026-04-01)


### Bug Fixes

* override path-to-regexp to resolve CVE-2026-4926 and CVE-2026-4923 ([2b267d6](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/2b267d62f458c1a8683ebedfdd66db3b8ac7db95))

## [1.0.1](https://github.com/bannaarr01/nestjs-keycloak-auth/compare/v1.0.0...v1.0.1) (2026-03-25)


### Features

* support array and object input formats for @Roles decorator ([e2c365d](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/e2c365d003388f9e6d2f045c844d9810b1a2783a))

# 1.0.0 (2026-03-22)


### Bug Fixes

* allows tokens issued after user revocation (new session) ([e6ce2b6](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/e6ce2b68261b3fd338365d6e05e853874faf8871))
* claim format ([c3fdb35](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/c3fdb3542a881b8ce7a7721bf22754e02dd1f12f))


### Features

* Back-channel logout + OAuth2 token scope validation ([9b2205d](https://github.com/bannaarr01/nestjs-keycloak-auth/commit/9b2205df3cbbcdba0c6e38990b232461fccd8dc5))
