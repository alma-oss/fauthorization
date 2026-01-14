F-Authorization
===============

[![NuGet](https://img.shields.io/nuget/v/Alma.Authorization.svg)](https://www.nuget.org/packages/Alma.Authorization)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Alma.Authorization.svg)](https://www.nuget.org/packages/Alma.Authorization)
[![Tests](https://github.com/alma-oss/fauthorization/actions/workflows/tests.yaml/badge.svg)](https://github.com/alma-oss/fauthorization/actions/workflows/tests.yaml)

> Library for a Web App Authorization, login, token, securing requests, ...

---

## Install

Add following into `paket.references`
```
Alma.Authorization
```

## Use

### Securer api calls

First of all you need to have an Api (defined in Shared project of your SAFE app).
```fs
// Shared
open Alma.Authorization

type IMyApi = {
    // Public actions
    Login: Username * Password -> AsyncResult<User, string>

    // Secured actions
    LoadGenericData: SecureRequest<unit> -> SecuredAsyncResult<Data list, string>
    LoadUserData: SecureRequest<unit> -> SecuredAsyncResult<Data list, string>
}
```

Then implement your Api.
```fs
// Init context
let currentApplication = {
    Authorization = {
        CurrentApplication = currentApplication.Gui.Instance    // CurrentApplication must be a Issuer and Audience for the validated token (use SessionJWT for this)
        AuthorizedBy = currentApplication.TokenKey              // AuthorizedBy is JWTKey used to authorize the token (read/validate current token)
        KeyForRenewToken = currentApplication.TokenKey          // This key will be used for renewed token (create/write new token)
    }
}

// Server

type MyErrorMessageType = MyErrorMessageType of string

module Api =
    open Shared
    open Feather.ErrorHandling
    open Alma.Authorization
    open Alma.Authorization.Session

    /// Helper operator, which allows the action authorization
    let inline private (>?>) authorize action =
        Authorize.authorizeAction
            current.Authorization
            MyErrorMessageType
            logAuthorizationError
            authorize
            action

    /// Helper operator, which allows you to access the Username from a sessionJWT
    let (>?>>) authorize action =
        Authorize.authorizeAction currentApplication.Authorization
            MyErrorMessageType
            logAuthorizationError
            authorize
            (Authorize.Action.RequestWithUsername action)

    let api = {
        //
        // Public actions
        //

        Login = fun credentials -> asyncResult {
            let! credentials =
                credentials
                |> Dto.Deserialize.credentials
                |> AsyncResult.ofResult <@> (CredentialsError.format >> ErrorMessage)

            let! user =
                credentials
                |> User.login // "transfer" credentials into a User
                |> AsyncResult.ofResult <@> (UserError.format >> ErrorMessage)

            return user |> Dto.Serialize.user
        }

        //
        // Secured actions
        //

        //                [..Authorization..]     [...         ... Api Endpoint function ...                ...]
        LoadGenericData = Authorize.withLogin >?> fun ( (* action parameters would go here *) ) -> asyncResult {
            let! data =
                Data.load () <@> (DataLoadError.format >> ErrorMessage)

            return data |> List.map Dto.Serialize.data
        }

        //             [..Authorization..]      [...         ... Api Endpoint function ...                ...]
        LoadUserData = Authorize.withLogin >?>> fun ((username: Username) (* action parameters would go here *) ) -> asyncResult {
            let! data =
                Data.loadForUser username <@> (DataLoadError.format >> ErrorMessage)

            return data |> List.map Dto.Serialize.data
        }
    }
```

### External Signing (e.g., Vault Transit)

For scenarios where you want to sign JWTs using an external service like HashiCorp Vault's Transit engine:

```fs
open Feather.ErrorHandling
open Alma.Authorization.JWT

// Create JWTKey with external signing
let jwtKey = JWTKey.External {
    Algorithm = "RS256"  // The JWT algorithm (RS256, ES256, etc.)
    Sign = fun unsignedJwt -> asyncResult {
        let! signature =
            unsignedJwt
            |> JWTPart.unsignedJWTValue
            |> Vault.signJWT    // call external API

        return JWTPart.Signature signature
    }
}

// Use it to create tokens
let! jwt =
    JWT.create
        (Issuer "my-app")
        (Audience "my-api")
        jwtKey
        (GenericTokenData.TokenData tokenData)
```

---

## Release
1. Increment version in `Alma.Authorization.fsproj`
2. Update `CHANGELOG.md`
3. Commit new version and tag it

## Development
### Requirements
- [dotnet core](https://dotnet.microsoft.com/learn/dotnet/hello-world-tutorial)

### Build
```bash
./build.sh build
```

### Tests
```bash
./build.sh -t tests
```
