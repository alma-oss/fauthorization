F-Authorization
===============

> Library for a Web App Authorization, login, token, securing requests, ...

---

## Install

Add following into `paket.dependencies`
```
source https://nuget.pkg.github.com/almacareer/index.json username: "%PRIVATE_FEED_USER%" password: "%PRIVATE_FEED_PASS%"
# LMC Nuget dependencies:
nuget Alma.Authorization
```

NOTE: For local development, you have to create ENV variables with your github personal access token.
```sh
export PRIVATE_FEED_USER='{GITHUB USERNANME}'
export PRIVATE_FEED_PASS='{TOKEN}'      # with permissions: read:packages
```

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
    LoadData: SecureRequest<unit> -> SecuredAsyncResult<Data list, string>
}
```

Then implement your Api.
```fs
// Server

type MyErrorMessageType = MyErrorMessageType of string

module Api =
    open Shared
    open Alma.ErrorHandling
    open Alma.Authorization
    open Alma.Authorization

    let inline private (>?>) authorize action =
        Authorize.authorizeAction
            (CurrentApplication currentApplication.Gui.SoftwareComponent)   // CurrentApplication must be a Issuer and Audience for the validated token
            (AuthorizedFor currentApplication.SoftwareComponent)            // AuthorizedFor is a software component which user want to do something needing authorization
            (KeyForRenewToken currentApplication.TokenKey)                  // This key will be used for renewed token, it must be one of the KeysForToken in order to access the renewed token again
            currentApplication.KeysForToken                                 // A list of keys, which will be used to try access a token (at least one of the keys must pass in order to grant a permission)
            MyErrorMessageType
            logAuthorizationError
            authorize
            action

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

                // [..Authorization..]     [...         ... Api Endpoint function ...                ...]
        LoadData = Authorize.withLogin >?> fun ( (* action parameters would go here *) ) -> asyncResult {
            let! data =
                Data.load () <@> (DataLoadError.format >> ErrorMessage)

            return data |> List.map Dto.Serialize.data
        }
    }
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
