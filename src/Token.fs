namespace Alma.Authorization

open System.IdentityModel.Tokens.Jwt
open Alma.Authorization.Common

[<RequireQualifiedAccess>]
type JWT =
    | Raw of Common.JWT
    | SecurityToken of JwtSecurityToken

module JWT =
    //
    // Errors
    //

    type JwtValidationError =
        | MissingKeyData
        | Unexpected of exn
        | TokenStatus of string
        | MissingUsername
        | MissingDisplayName
        | MissingGroups

    type AuthorizationError =
        | JwtValidationError of JwtValidationError
        | ActionIsNotGranted of string
        | RequestError of ErrorMessage

    //
    // Types
    //

    [<RequireQualifiedAccess>]
    module UserCustomData =
        let [<Literal>] Username = "username"
        let [<Literal>] DisplayName = "user"
        let [<Literal>] Groups = "groups"

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

    let (|HasUsername|_|) = function
        | HasPayloadValue UserCustomData.Username (JWTValue.String username) -> Some username
        | _ -> None

    let (|HasDisplayName|_|) = function
        | HasPayloadValue UserCustomData.DisplayName (JWTValue.String displayName) -> Some displayName
        | _ -> None

    [<RequireQualifiedAccess>]
    type CustomItem =
        | String of string * string
        | Strings of string * (string list)

    [<AutoOpen>]
    module JwtKeyModule =
        type JWTKey =
            private
            | JWTKey of System.Guid
            | ServiceAccount of Password
            | Local of string

        [<RequireQualifiedAccess>]
        module JWTKey =
            let generate () =
                System.Guid.NewGuid()
                |> JWTKey

            let create = ServiceAccount

            /// Keep in mind, that using static key is not secure
            let local value = Local value

            let value = function
                | JWTKey key -> key.ToString()
                | ServiceAccount (Password password) -> password
                | Local value -> value

    type PermissionGroup = PermissionGroup of string

    [<RequireQualifiedAccess>]
    module PermissionGroup =
        let value (PermissionGroup group) = group

    type Permission =
        | ValidToken
        | Group of PermissionGroup

    [<RequireQualifiedAccess>]
    module SymmetricJWT =
        open System
        open JsonWebToken
        open Alma.ServiceIdentification
        open Alma.ErrorHandling
        open Alma.ErrorHandling.Result.Operators

        type private GrantedToken = GrantedToken of Jwt

        type private UserData = {
            Username: string
            DisplayName: string
            Groups: PermissionGroup list
            GrantedToken: GrantedToken
        }

        type GrantedTokenData = private GrantedTokenData of UserData

        let value (JWT value) = value

        let private readUserData currentApp key (JWT token) =
            try
                use key = new SymmetricJwk(key |> JWTKey.value)
                let currentInstance = currentApp |> Instance.concat "-"

                let policy =
                    TokenValidationPolicyBuilder()
                        .RequireSignature(key, SignatureAlgorithm.HmacSha256)
                        .RequireIssuer(currentInstance)
                        .RequireAudience(currentInstance)
                        .EnableLifetimeValidation(true, 10)
                        .Build()

                let jwtResult = JwtReader().TryReadToken(token, policy)

                if jwtResult.Succedeed then
                    result {
                        let! username =
                            match jwtResult.Token.Payload.TryGetValue(UserCustomData.Username) with
                            | true, username -> Ok (username.Value.ToString())
                            | _ -> Error MissingUsername

                        let! displayName =
                            match jwtResult.Token.Payload.TryGetValue(UserCustomData.DisplayName) with
                            | true, user -> Ok (user.Value.ToString())
                            | _ -> Error MissingDisplayName

                        let! groups =
                            match jwtResult.Token.Payload.TryGetValue(UserCustomData.Groups) with
                            | true, groups ->
                                match groups.Value with
                                | :? JwtArray as groups ->
                                    groups
                                    |> Seq.map (fun i -> PermissionGroup (i.Value.ToString()))
                                    |> Seq.toList
                                    |> Ok
                                | _ -> Error MissingGroups
                            | _ -> Error MissingGroups

                        return GrantedTokenData {
                            Username = username
                            DisplayName = displayName
                            Groups = groups
                            GrantedToken = GrantedToken jwtResult.Token
                        }
                    }
                else
                    jwtResult.Status.ToString()
                    |> TokenStatus
                    |> Error
            with
            | e -> Error (Unexpected e)

        let internal username currentApplication key token =
            token
            |> readUserData currentApplication key
            |> Result.map (fun (GrantedTokenData { Username = username }) -> Username username)

        let isGranted currentApp keysForToken token requiredPermission = result {
            let allUserData =
                keysForToken
                |> List.map (fun key ->
                    token
                    |> readUserData currentApp key
                    <@> JwtValidationError
                )

            let! userData =
                match allUserData with
                | [] ->
                    Error (JwtValidationError MissingKeyData)

                | onlyErrors when onlyErrors |> List.forall (function | Error _ -> true | _ -> false) ->
                    onlyErrors
                    |> List.head

                | atLeastOneGranted when atLeastOneGranted |> List.exists (function | Ok _ -> true | _ -> false) ->
                    atLeastOneGranted
                    |> List.pick (function
                        | Ok data -> Some (Ok data)
                        | _ -> None
                    )

                | firstError ->
                    firstError
                    |> List.pick (function
                        | Error error -> Some (Error error)
                        | _ -> None
                    )

            return!
                match requiredPermission with
                | ValidToken -> Ok userData
                | Group requiredGroup ->
                    match userData with
                    | GrantedTokenData { Groups = groups } when groups |> List.exists ((=) requiredGroup) -> Ok userData
                    | _ -> Error (ActionIsNotGranted "You are not authorized for this action.")
        }

        let rec private addCustomData customData (descriptor: JwsDescriptor) =
            match customData with
            | [] -> descriptor

            | CustomItem.String (key, value) :: rest ->
                descriptor.AddClaim(key, value)
                descriptor |> addCustomData rest

            | CustomItem.Strings (key, values) :: rest ->
                let jwtValue (value: string) = JwtValue(value)

                let array =
                    values
                    |> List.map jwtValue
                    |> List.toGeneric
                    |> JwtArray

                descriptor.AddClaim(key, array)
                descriptor |> addCustomData rest

        let create currentApp appKey customData =
            use key = new SymmetricJwk(appKey |> JWTKey.value, SignatureAlgorithm.HmacSha256)
            let currentInstance = currentApp |> Instance.concat "-"
            let now = DateTime.UtcNow

            JwsDescriptor(
                SigningKey = key,
                JwtId = Guid.NewGuid().ToString(),
                IssuedAt = (now |> Nullable),
                NotBefore = (now |> Nullable),
                ExpirationTime = (now.AddMinutes(30.0) |> Nullable),
                Issuer = currentInstance,
                Audience = currentInstance
            )
            |> addCustomData customData
            |> JwtWriter().WriteTokenString
            |> JWT

        let renew appKey (GrantedTokenData userData) =
            use key = new SymmetricJwk(appKey |> JWTKey.value, SignatureAlgorithm.HmacSha256)

            let (GrantedToken token) = userData.GrantedToken
            let customData = [
                CustomItem.String (UserCustomData.Username, userData.Username)
                CustomItem.String (UserCustomData.DisplayName, userData.DisplayName)
                CustomItem.Strings (UserCustomData.Groups, userData.Groups |> List.map PermissionGroup.value)
            ]

            JwsDescriptor(
                SigningKey = key,
                JwtId = Guid.NewGuid().ToString(),
                IssuedAt = token.IssuedAt,
                NotBefore = token.NotBefore,
                ExpirationTime = (DateTime.UtcNow.AddMinutes(30.0) |> Nullable),
                Issuer = token.Issuer,
                Audience = (token.Audiences |> Seq.head)
            )
            |> addCustomData customData
            |> JwtWriter().WriteTokenString
            |> JWT

    [<RequireQualifiedAccess>]
    module internal RenewedToken =
        let username currentApplication key (RenewedToken token) =
            token |> SymmetricJWT.username currentApplication key
