# Changelog

<!-- There is always Unreleased section on the top. Subsections (Add, Changed, Fix, Removed) should be Add as needed. -->
## Unreleased
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
