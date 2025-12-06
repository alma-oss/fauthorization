namespace Alma.Authorization

open Alma.Authorization.Common

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

type Authenticate = Authenticate of (Credentials -> Result<User, string>)

[<RequireQualifiedAccess>]
module User =
    let login (Authenticate auth) = auth

type ACLClient = {
    ClientName: string
    ClientId: string
    Origin: string
}

[<RequireQualifiedAccess>]
module ACLClient =
    open FSharp.Data
    open Microsoft.Extensions.Logging
    open Feather.ErrorHandling

    type private ACLClientSchema = JsonProvider<"src/schema/aclClient.json", SampleIsList = true>

    let tryParse value =
        try
            let parsed = ACLClientSchema.Parse(value)
            Some {
                ClientName = parsed.ClientName
                ClientId = parsed.ClientId
                Origin = parsed.Origin
            }
        with _ -> None

    let parseList value =
        try
            ACLClientSchema.ParseList(value)
            |> Seq.map (fun item ->
                {
                    ClientName = item.ClientName
                    ClientId = item.ClientId
                    Origin = item.Origin
                }
            )
            |> Seq.toList
            |> Ok
        with e -> Error e

    let fromEnvironmentVariable (loggerFactory: ILoggerFactory) getEnvironmentValue (variableName: string) = result {
            let logger = loggerFactory.CreateLogger("ACLClient")
            let! (serializedClients: string) =
                variableName
                |> getEnvironmentValue
                    id
                    (sprintf "ACL Clients are not defined. It should be in the environment variable %A.")

            return!
                serializedClients
                |> parseList
                |> Result.bindError (fun _ ->
                    logger.LogDebug("Retry to parse ACL Clients with un-escaped quotes")

                    serializedClients.Replace("\\\"", "\"")
                    |> parseList
                )
                |> Result.mapError (sprintf "%A")
        }
