---
name: fauthorization
description: >-
  Use whenever generating or reviewing F# code that creates, validates, renews, or
  composes JWT-based web app authorization with the Alma.Authorization library. Trigger on
  JWT.create, JWT.createWithId, JWT.authorize, JWT.renew, SessionJWT.create/authorize/renew,
  JWTKey.Symmetric / Asymmetric / External (Vault Transit external signing), the
  Session.Authorize.withLogin / withGroup / withScope flow, the >?> and >?>> authorization
  operators, SecureRequest / SecuredAsyncResult endpoints, Casbin RBAC via
  Authorization.createEnforcer / enforce / enforceWithPurpose, Scope / Capability parsing,
  and AmazonJWT (AWS ALB x-amzn-oidc-data) validation. Use for securing SAFE-stack API
  endpoints, token renewal, group/scope checks, and reading claims (HasJWTAuthorization,
  HasClientId, HasUsername).
---

# F-Authorization

Library: [fauthorization](https://github.com/alma-oss/fauthorization)
NuGet: `Alma.Authorization`

## Purpose

`Alma.Authorization` is an F# library for web app authorization. It creates and validates
JWTs (symmetric, asymmetric, or externally signed), runs a session-based authorize-then-renew
flow for securing API endpoints, enforces RBAC with Casbin, and validates Amazon ALB OIDC
tokens. It is built around composable `Result`/`AsyncResult` computation expressions.

## When to Use

- Securing API endpoints with token validation plus automatic token renewal.
- Creating, signing, validating, or renewing JWTs (including external/Vault signing).
- Checking a caller's group membership or an RBAC scope before running an action.
- Reading claims (username, client id, groups) from an incoming bearer token.
- Validating JWTs issued by an AWS Application Load Balancer.

## When NOT to Use

- Pure transport/HTTP concerns, routing, or serialization — those belong in the host app.
- Defining business rules or per-project roles — this library only enforces them.
- Generating UI or client-side token storage — handled by the consuming SAFE app.

## Main Concepts

- `JWT` (module in `Token.fs`) — low-level token creation, validation, parsing, renewal.
- `JWT.JWT` — a token wrapper, either `Raw` or a parsed `SecurityToken`.
- `JWTKey` — signing/validation key: `Symmetric` (GUID/HMAC), `Asymmetric` (RSA/ECDSA PEM), or `External` (async `Sign` callback).
- `Requirement` — validation constraints: `NotExpired`, `IssuedBy`, `IntendedFor`.
- `Permission` — authorization predicate: `ValidToken`, `Group`, or `TokenData` predicate.
- `SessionData` / `TokenData` — claim payloads (username, display name, groups, custom claims).
- `GenericTokenData` — input to `JWT.create`: `TokenData`, `CustomItems`, or `SessionData`.
- `SessionJWT` — opinionated session tokens where issuer = audience = current `Instance`.
- `Scope` / `Capability` / `Object` — RBAC scope parsed from an `"object:capability"` string.
- `Authorization` (module) — Casbin RBAC: `createEnforcer`, `enforce`, `enforceWithPurpose`.
- `Session.Authorization` — record of `CurrentApplication`, `AuthorizedBy`, `KeyForRenewToken`.
- `Session.Authorize` — endpoint guards `withLogin` / `withGroup` / `withScope` plus `authorizeAction`.
- `Action` — the secured endpoint body: `Request` or `RequestWithUsername`.
- `SecureRequest<'Data>` — wraps a `SecurityToken` and request data for every secured call.
- `AmazonJWT` — validates AWS ALB OIDC tokens and mints a `SessionJWT` from them.

## Related Libraries

- `Alma.Authorization.Common` — shared `User`, `Username`, `Password`, `JWT`, `SecureRequest`, `RenewedToken`, `SecuredRequestError`, `SecuredAsyncResult`.
- `Alma.ServiceIdentification` — `Instance`, `Issuer`, `Audience`, `Purpose`, `Create.Instance`.
- `Feather.ErrorHandling` — `AsyncResult`/`Result` CEs and operators (`<@>`, `>=>`).
- `Casbin.NET` — RBAC policy engine behind the `Authorization` module.

## Keywords for Search

JWT, SessionJWT, JWTKey, Symmetric, Asymmetric, External signing, Vault Transit, Issuer,
Audience, Requirement, NotExpired, Permission, Group, Scope, Capability, Casbin, Enforcer,
RBAC, enforce, enforceWithPurpose, SecureRequest, Authorize, withLogin, withGroup, withScope,
authorizeAction, RenewedToken, SecuredAsyncResult, HasJWTAuthorization, HasClientId,
HasUsername, AmazonJWT, x-amzn-oidc-data, SAFE stack, F# authorization.

## Reference Files

- For composition principles and recommended API usage, read `references/preferred-patterns.md`.
- For known pitfalls and incorrect assumptions, read `references/anti-patterns.md`.
- For worked, self-contained code examples, read `references/examples.md`.
