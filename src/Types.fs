namespace Lmc.Authorization

open Lmc.Authorization.Common

//
// Errors
//

type CredentialsError =
    | EmptyUsername
    | EmptyPassword
    | EmptyCredentials

[<RequireQualifiedAccess>]
module CredentialsError =
    let format = function
        | EmptyUsername -> "You have to pass in a credentials. Username is missing."
        | EmptyPassword -> "You have to pass in a credentials. Password is missing."
        | EmptyCredentials -> "You have to pass in a credentials. Both Username and Password are missing."

//
// Types
//

type Credentials = {
    Username: Username
    Password: Password
}

[<RequireQualifiedAccess>]
module Credentials =
    let deserialize: Username * Password -> Result<Credentials, CredentialsError> = function
        | Username "", Password "" -> Error EmptyCredentials
        | Username "", _ -> Error EmptyUsername
        | _, Password "" -> Error EmptyPassword
        | username, password -> Ok { Username = username; Password = password }
