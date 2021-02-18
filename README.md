F-Authorization
===============

> Library for a Web App Authorization, login, token, securing requests, ...

---

## Install

Add following into `paket.dependencies`
```
git ssh://git@bitbucket.lmc.cz:7999/archi/nuget-server.git master Packages: /nuget/
# LMC Nuget dependencies:
nuget Lmc.Authorization
```

Add following into `paket.references`
```
Lmc.Authorization
```

## Use

### Securer api calls

First of all you need to have an Api (defined in Shared project of your SAFE app).
```fs
// Shared
open Lmc.Authorization.Common

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
    open Lmc.ErrorHandling
    open Lmc.Authorization
    open Lmc.Authorization.Common

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

## Release
1. Increment version in `Authorization.fsproj`
2. Update `CHANGELOG.md`
3. Commit new version and tag it
4. Run `$ fake build target release`
5. Go to `nuget-server` repo, run `faket build target copyAll` and push new versions

## Development
### Requirements
- [dotnet core](https://dotnet.microsoft.com/learn/dotnet/hello-world-tutorial)
- [FAKE](https://fake.build/fake-gettingstarted.html)

### Build
```bash
fake build
```

### Watch
```bash
fake build target watch
```
