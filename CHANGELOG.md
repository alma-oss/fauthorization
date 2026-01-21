# Changelog

<!-- There is always Unreleased section on the top. Subsections (Add, Changed, Fix, Removed) should be Add as needed. -->
## Unreleased
- Add `Capability.Other` case
- [**BC**] Remove `CapabilityParseError` type and module
- Add `Scope.value` function
- [**BC**] Change types of `Requirement` cases
    - `IssuedBy`
    - `IntendedFor`

## 8.1.0 - 2026-01-20
- Add `Authorization` module with Casbin
- Add `EnforceScope` type and module
- Add `Session.Authorize.withScope` function
- Add `JWT.TokenData` field `Subject`

## 8.0.0 - 2026-01-14
- [**BC**] Rename
    - `SymmetricJWT` module to `SessionJWT`
    - `RenewedToken` to `RenewedSessionToken`
- Add *generic* `JWT` module
- [**BC**] Move `Authorize` module etc. under the `Session` module and simplify the internals
- [**BC**] Drop cases/types
    - `JWTKey.Local`
    - `AuthorizedBy`
- Add `JWT.Common` member
- [**BC**] Move symmetric key function under `JWTKey.Symmetric` module
- Add cases/types/modules
    - `JWTPart`
    - `JWTKey.AsymmetricKey`
    - `JWTKey.External`
    - `JwtValidationError.InvalidKey`
    - `AuthorizationError.InvalidKey`
    - `Issuer`
    - `Audience`
    - `ExpiresIn`
    - `GenericTokenData`
- Add types for Asymmetric keys and more detailed JWT manipulations
- Add `AmazonJWT` module

## 7.0.0 - 2025-12-06
- [**BC**] Move repository
- [**BC**] Remove AWS JWT

## 6.0.0 - 2025-03-17
- [**BC**] Use net9.0

## 5.1.0 - 2024-06-06
- Add `AmazonJWT` module
- Add `AmazonJWT.Authenticate` module

## 5.0.0 - 2024-06-05
- Add `Action` type with 2 cases
    - `Request` - the previous action, same as it was before
    - `RequestWithUsername` - new case which allows to get a username out of a renewed token
- [**BC**] Change `authorizeAction` parameter `action` to be a type `Action`

## 4.2.0 - 2024-05-23
- Add types and modules
    - `Authorize`
    - `AuthorizedBy`
    - `Authorization`

## 4.1.0 - 2024-05-21
- Add types and functions to `JWT` module
    - `AuthorizationError`
    - `CustomItem`
    - `HasDisplayNam`
    - `HasUsername`
    - `JWTKey`
    - `JwtValidationError`
    - `Permission`
    - `PermissionGroup`
    - `SymmetricJWT`
    - `UserCustomData`
- Add `Authenticate` type
- Add `User` module

## 4.0.0 - 2024-01-30
- [**BC**] Use net8.0
- [**BC**] Use Alma namespace
- Fix project metadata
- [**BC**] Refactor `JWT` and `Authorization` modules

## 3.0.0 - 2021-02-18
- Add `KeyForRenewToken` type to explicitly mark a JWTKey purpose
- Add `CurrentApplication` type to explicitly mark a SoftwareComponent which is the Issuer and Audience of the user token
- Add `AuthorizedFor` type to explicitly mark a SoftwareComponent which is part of the checked eligibility (permission group)
- [**BC**] Use types above in `Authorize.authorizeAction` function

## 2.2.0 - 2021-02-16
- Update dependencies

## 2.1.0 - 2021-01-21
- Add `Credentials` and `CredentialsError` type and module

## 2.0.0 - 2021-01-20
- [**BC**] Make `Authorize.authorizeAction` function really generic by adding a `formatError` function
- [**BC**] Rename `Authorize.authorizeAction` to `Authorize.action`

## 1.0.0 - 2021-01-21
- Initial implementation
