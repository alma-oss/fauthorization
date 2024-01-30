namespace Alma.Authorization

open System.Net
open System.Net.Http
open System.IdentityModel.Tokens.Jwt
open Alma.Authorization.Common

[<RequireQualifiedAccess>]
type JWT =
    | Raw of Common.JWT
    | SecurityToken of JwtSecurityToken

module JWT =
    [<RequireQualifiedAccess>]
    module private JWTSecurityToken =
        let parse (JWT token) =
            let jwtHandler = JwtSecurityTokenHandler()
            jwtHandler.ReadJwtToken(token)

    let (|IsJWT|_|) token =
        try token |> JWT |> JWTSecurityToken.parse |> JWT.SecurityToken |> Some
        with _ -> None

    type JWTValue =
        | String of string
        | Int of int
        | Int64 of int64
        | Bool of bool

    [<RequireQualifiedAccess>]
    module JWTValue =
        let tryParsePayload (payload: JwtPayload) =
            payload
            |> Seq.choose (fun kv ->
                match kv.Value with
                | :? string as value -> Some (kv.Key, String value)
                | :? int as value -> Some (kv.Key, Int value)
                | :? int64 as value -> Some (kv.Key, Int64 value)
                | :? bool as value -> Some (kv.Key, Bool value)
                | _ -> None
            )
            |> Seq.toList

        let (|Has|_|) key payloadValues =
            payloadValues
            |> List.tryPick (function
                | (key', value) when key = key' -> Some value
                | _ -> None
            )

    type JWTClientId = JWTClientId of string

    let (|HasJWTAuthorization|_|) (headers: Map<string, string>) =
        match headers |> Map.tryFind "Authorization" with
        | Some (Regex "Bearer (.+)" [ IsJWT token ]) -> Some token
        | _ -> None

    let (|HasPayloadValue|_|) key = function
        | JWT.Raw (Common.JWT (IsJWT (JWT.SecurityToken jwt)))
        | JWT.SecurityToken jwt ->
            match jwt.Payload |> JWTValue.tryParsePayload with
            | JWTValue.Has key value -> Some value
            | _ -> None
        | _ -> None

    let (|HasClientId|_|) = function
        | HasPayloadValue "client_id" (JWTValue.String clientId) -> Some (JWTClientId clientId)
        | _ -> None

module Test =
    let x () =
        let headers = ["Authorization", "Bearer token"] |> Map.ofList

        let client =
            match headers with
            | JWT.HasJWTAuthorization (JWT.HasClientId (JWT.JWTClientId clientId)) -> clientId
            | _ -> ""
        ()
