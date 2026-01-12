namespace Alma.Authorization

open System
open System.Text
open System.IdentityModel.Tokens.Jwt
open Alma.Authorization.Common

[<RequireQualifiedAccess>]
type JWT =
    | Raw of Common.JWT
    | SecurityToken of Common.JWT * JwtSecurityToken

    with
        member this.Common =
            match this with
            | Raw jwt -> jwt
            | SecurityToken (jwt, _) -> jwt

module JWT =
    open Alma.ServiceIdentification
    open Feather.ErrorHandling
    open Feather.ErrorHandling.Result.Operators

    //
    // Errors
    //

    type JwtValidationError =
        | InvalidKey of string
        | MissingKeyData
        | Unexpected of exn
        | TokenStatus of string
        | MissingUsername
        | MissingDisplayName
        | MissingGroups

    type AuthorizationError =
        | InvalidKey of string
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
        try
            let jwt = JWT token
            let parsed = jwt |> JWTSecurityToken.parse

            JWT.SecurityToken (jwt, parsed) |> Some
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

    let (|HasJWTAuthorization|_|) (headers: Map<string, string>): JWT option =
        match headers |> Map.tryFind "Authorization" with
        | Some (Regex "Bearer (.+)" [ IsJWT token ]) -> Some token
        | _ -> None

    let (|HasPayloadValue|_|) key = function
        | JWT.Raw (Common.JWT (IsJWT (JWT.SecurityToken (_, jwt))))
        | JWT.SecurityToken (_, jwt) ->
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
        type SupportedAsymmetricAlgorithmsFamily =
            | Rsa
            | Ecdsa

        type Pem = {
            Pem: string
            Algorithm: SupportedAsymmetricAlgorithmsFamily
        }

        type PublicPem = PublicPem of Pem
        type PrivatePem = PrivatePem of Pem

        type SymmetricJWTKey =
            internal
            | JWTKey of Guid

        type AsymmetricJWTKey =
            internal
            | Public of PublicPem
            | Private of PrivatePem

        type JWTKey =
            | Symmetric of SymmetricJWTKey
            | Asymmetric of AsymmetricJWTKey

        [<RequireQualifiedAccess>]
        module JWTKey =
            open System.Security.Cryptography
            open JsonWebToken

            let internal signatureAlgorithm = function
                | Symmetric _ -> SignatureAlgorithm.HmacSha256
                | Asymmetric (Public (PublicPem { Algorithm = alg }))
                | Asymmetric (Private (PrivatePem { Algorithm = alg })) ->
                    match alg with
                    | Rsa -> SignatureAlgorithm.RsaSha256
                    | Ecdsa -> SignatureAlgorithm.EcdsaSha256

            [<RequireQualifiedAccess>]
            module Symmetric =
                let generate () = Guid.NewGuid() |> JWTKey

                let tryParse (value: string) =
                    match Guid.TryParse value with
                    | true, guid -> Some (JWTKey guid)
                    | _ -> None

                let value = function
                    | JWTKey key -> key.ToString()

                let internal toSymmetricJwk key =
                    new SymmetricJwk(key |> value, SignatureAlgorithm.HmacSha256) :> Jwk

            [<RequireQualifiedAccess>]
            module Asymmetric =
                let publicPem pem = PublicPem pem |> Public
                let privatePem pem = PrivatePem pem |> Private

                let value = function
                    | Public (PublicPem pem) -> pem
                    | Private (PrivatePem pem) -> pem

                let private pemToJwk = function
                    | { Pem = pem; Algorithm = Rsa } ->
                        use rsa = RSA.Create()
                        rsa.ImportFromPem(pem)
                        let rsaParams = rsa.ExportParameters(false)

                        new RsaJwk(rsaParams, SignatureAlgorithm.RsaSha256) :> Jwk

                    | { Pem = pem; Algorithm = Ecdsa } ->
                        use ecdsa = ECDsa.Create()
                        ecdsa.ImportFromPem(pem)
                        let ecParams = ecdsa.ExportParameters(false)

                        new ECJwk(ecParams, SignatureAlgorithm.EcdsaSha256) :> Jwk

                let internal toPublicJwk = function
                    | Public (PublicPem pem) -> pemToJwk pem |> Some
                    | _ -> None

                let internal toPrivateJwk = function
                    | Private (PrivatePem pem) -> pemToJwk pem |> Some
                    | _ -> None

            let internal readKey = function
                | Symmetric symmetricKey -> symmetricKey |> Symmetric.toSymmetricJwk |> Ok
                | Asymmetric asymmetricKey -> asymmetricKey |> Asymmetric.toPublicJwk |> Result.ofOption "Wrong key type, expected public key"

            let internal writeKey = function
                | Symmetric symmetricKey -> symmetricKey |> Symmetric.toSymmetricJwk |> Ok
                | Asymmetric asymmetricKey -> asymmetricKey |> Asymmetric.toPrivateJwk |> Result.ofOption "Wrong key type, expected private key"

    type Issuer = Issuer of string
    type Audience = Audience of string

    type Requirement =
        | NotExpired
        | IssuedBy of Instance
        | IntendedFor of Instance

    type PermissionGroup = PermissionGroup of string

    type TokenData = {
        Username: string option
        DisplayName: string option
        Groups: PermissionGroup list
        Scope: string option
        Issuer: string option
        Expiration: DateTimeOffset option
        ClientId: string option
        Name: string option
        FamilyName: string option
        GivenName: string option
        Picture: string option
        Email: string option
        Client: string option
    }

    [<RequireQualifiedAccess>]
    type GenericTokenData =
        | TokenData of TokenData
        | CustomItems of CustomItem list

    [<RequireQualifiedAccess>]
    module PermissionGroup =
        let value (PermissionGroup group) = group

    type Permission =
        | ValidToken
        | Group of PermissionGroup
        | TokenData of (TokenData -> bool)

    [<RequireQualifiedAccess>]
    module private TokenData =
        let toCustomItems data =
            List.choose id [
                data.Username |> Option.map (fun u -> CustomItem.String (UserCustomData.Username, u))
                data.DisplayName |> Option.map (fun d -> CustomItem.String (UserCustomData.DisplayName, d))

                match data.Groups with
                | [] -> None
                | groups -> Some (CustomItem.Strings (UserCustomData.Groups, groups |> List.map PermissionGroup.value))

                data.Scope |> Option.map (fun s -> CustomItem.String ("scope", s))
                data.ClientId |> Option.map (fun c -> CustomItem.String ("client_id", c))
                data.Name |> Option.map (fun n -> CustomItem.String ("name", n))
                data.FamilyName |> Option.map (fun f -> CustomItem.String ("family_name", f))
                data.GivenName |> Option.map (fun g -> CustomItem.String ("given_name", g))
                data.Picture |> Option.map (fun p -> CustomItem.String ("picture", p))
                data.Email |> Option.map (fun e -> CustomItem.String ("email", e))
                data.Client |> Option.map (fun c -> CustomItem.String ("client", c))
            ]

    open JsonWebToken

    [<AutoOpen>]
    module internal JWTResult =
        let getPayloadValue (jwtResult: TokenValidationResult) (key: string) =
            match jwtResult.Token.Payload.TryGetValue(key) with
            | true, value -> Some (value.Value.ToString())
            | _ -> None

        let getHeaderValue (jwtResult: TokenValidationResult) (key: string) =
            let keyBytes = Text.Encoding.UTF8.GetBytes(key)
            match jwtResult.Token.Header.TryGetValue(ReadOnlySpan(keyBytes)) with
            | true, value -> Some (value.Value.ToString())
            | _ -> None

        let tryParseDateTimeOffset (value: obj) =
            match value with
            | :? int64 as unixTime -> Some (DateTimeOffset.FromUnixTimeSeconds(unixTime))
            | :? int as unixTime -> Some (DateTimeOffset.FromUnixTimeSeconds(int64 unixTime))
            | _ -> None

        let getDateTimeOffset (jwtResult: TokenValidationResult) (key: string) =
            match jwtResult.Token.Payload.TryGetValue(key) with
            | true, value -> value.Value |> tryParseDateTimeOffset
            | _ -> None

        let getGroups (jwtResult: TokenValidationResult) (key: string) =
            match jwtResult.Token.Payload.TryGetValue(key) with
            | true, groups ->
                match groups.Value with
                | :? JwtArray as groups ->
                    groups
                    |> Seq.map (fun i -> PermissionGroup (i.Value.ToString()))
                    |> Seq.toList
                | _ -> []
            | _ -> []

    //
    // Generic JWT
    //

    [<RequireQualifiedAccess>]
    module JWT =
        let common (jwt: JWT) = jwt.Common
        let value = common >> JWT.value

        type internal GrantedToken = GrantedToken of Jwt

        type GrantedTokenData = internal GrantedTokenData of GrantedToken * TokenData

        type internal Authorize = JWTKey -> Permission -> Common.JWT -> Result<GrantedTokenData, AuthorizationError>
        type internal Renew = JWTKey -> GrantedTokenData -> Result<RenewedToken, string>

        let tokenData (GrantedTokenData (_, tokenData)) = tokenData

        let internal readTokenData (jwtKey: JWTKey) requirements (JWT token) = result {
            try
                use! key = jwtKey |> JWTKey.readKey <@> JwtValidationError.InvalidKey

                let policyBuilder =
                    TokenValidationPolicyBuilder()
                        .RequireSignature(key, JWTKey.signatureAlgorithm jwtKey)

                let policyBuilder =
                    requirements
                    |> List.fold (fun (builder: TokenValidationPolicyBuilder) -> function
                        | NotExpired -> builder.EnableLifetimeValidation(true, 10)
                        | IssuedBy instance -> builder.RequireIssuer(instance |> Instance.concat "-")
                        | IntendedFor instance -> builder.RequireAudience(instance |> Instance.concat "-")
                    ) policyBuilder

                let policy = policyBuilder.Build()

                let jwtResult = JwtReader().TryReadToken(token, policy)

                if jwtResult.Succedeed then
                    return
                        GrantedTokenData (GrantedToken jwtResult.Token, {
                            Username = getPayloadValue jwtResult UserCustomData.Username
                            DisplayName = getPayloadValue jwtResult UserCustomData.DisplayName
                            Groups = getGroups jwtResult UserCustomData.Groups
                            Scope = getPayloadValue jwtResult "scope"
                            Issuer = getPayloadValue jwtResult "iss"
                            Expiration = getDateTimeOffset jwtResult "exp"
                            ClientId = getPayloadValue jwtResult "client_id"
                            Name = getPayloadValue jwtResult "name"
                            FamilyName = getPayloadValue jwtResult "family_name"
                            GivenName = getPayloadValue jwtResult "given_name"
                            Picture = getPayloadValue jwtResult "picture"
                            Email = getPayloadValue jwtResult "email"
                            Client = getHeaderValue jwtResult "client"
                        })
                else
                    return!
                        jwtResult.Status.ToString()
                        |> TokenStatus
                        |> Error
            with
            | e -> return! Error (Unexpected e)
        }

        let internal validatePermissions grantedTokenData = function
            | ValidToken -> Ok grantedTokenData
            | Group requiredGroup ->
                match grantedTokenData with
                | GrantedTokenData (_, { Groups = groups }) when groups |> List.exists ((=) requiredGroup) -> Ok grantedTokenData
                | _ -> Error (ActionIsNotGranted "You are not authorized for this action.")
            | TokenData predicate ->
                match grantedTokenData with
                | GrantedTokenData (_, grantedUserData) when predicate grantedUserData -> Ok grantedTokenData
                | _ -> Error (ActionIsNotGranted "You are not authorized for this action.")

        let internal authorizeToken readTokenData requiredPermission (token: Common.JWT) = result {
            let! tokenData = token |> readTokenData <@> JwtValidationError

            return! requiredPermission |> validatePermissions tokenData
        }

        let authorize requirements: Authorize = fun jwtKey ->
            authorizeToken (readTokenData jwtKey requirements)

        let rec internal addCustomData customData (descriptor: JwsDescriptor) =
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

        let create (Issuer issuer) (Audience audience) (jwtKey: JWTKey) customData = result {
            use! key = jwtKey |> JWTKey.writeKey
            let now = DateTime.UtcNow

            let descriptor = JwsDescriptor(
                SigningKey = key,
                JwtId = Guid.NewGuid().ToString(),
                IssuedAt = (now |> Nullable),
                NotBefore = (now |> Nullable),
                ExpirationTime = (now.AddMinutes(30.0) |> Nullable),
                Issuer = issuer,
                Audience = audience
            )

            let customData =
                match customData with
                | GenericTokenData.TokenData data -> TokenData.toCustomItems data
                | GenericTokenData.CustomItems items -> items

            return
                descriptor
                |> addCustomData customData
                |> JwtWriter().WriteTokenString
                |> JWT
        }

        let renew: Renew = fun jwtKey (GrantedTokenData (GrantedToken token, tokenData)) -> result {
            use! key = jwtKey |> JWTKey.writeKey

            return
                JwsDescriptor(
                    SigningKey = key,
                    JwtId = Guid.NewGuid().ToString(),
                    IssuedAt = token.IssuedAt,
                    NotBefore = token.NotBefore,
                    ExpirationTime = (DateTime.UtcNow.AddMinutes(30.0) |> Nullable),
                    Issuer = token.Issuer,
                    Audience = (token.Audiences |> Seq.head)
                )
                |> addCustomData (tokenData |> TokenData.toCustomItems)
                |> JwtWriter().WriteTokenString
                |> JWT
                |> RenewedToken
        }

    [<RequireQualifiedAccess>]
    module SessionJWT =
        type SessionData = {
            Username: string
            DisplayName: string
            Groups: PermissionGroup list
        }

        type GrantedSessionData = private GrantedSessionData of JWT.GrantedTokenData * SessionData

        type private Authorize = SymmetricJWTKey -> Permission -> Common.JWT -> Result<GrantedSessionData, AuthorizationError>
        type private Renew = SymmetricJWTKey -> GrantedSessionData -> Result<RenewedToken, string>

        [<RequireQualifiedAccess>]
        module private SessionData =
            let toCustomItems sessionData =
                [
                    CustomItem.String (UserCustomData.Username, sessionData.Username)
                    CustomItem.String (UserCustomData.DisplayName, sessionData.DisplayName)
                    CustomItem.Strings (UserCustomData.Groups, sessionData.Groups |> List.map PermissionGroup.value)
                ]

            let fromTokenData (JWT.GrantedTokenData (_, tokenData)) = result {
                let! username = tokenData.Username |> Result.ofOption MissingUsername
                let! displayName = tokenData.DisplayName |> Result.ofOption MissingDisplayName

                let! groups =
                    match tokenData.Groups with
                    | [] -> Error MissingGroups
                    | groups -> Ok groups

                return {
                    Username = username
                    DisplayName = displayName
                    Groups = groups
                }
            }

        [<RequireQualifiedAccess>]
        module private RawGrantedSessionData =
            let sessionData (GrantedSessionData (_, sessionData)) = sessionData

        [<RequireQualifiedAccess>]
        module GrantedSessionData =
            let userName = RawGrantedSessionData.sessionData >> _.Username >> Username
            let displayName = RawGrantedSessionData.sessionData >> _.DisplayName

        let private readSessionData currentApplication key token = result {
            let! grantedData =
                token
                |> JWT.readTokenData key [
                    NotExpired
                    IssuedBy currentApplication
                    IntendedFor currentApplication
                ]

            let! sessionData = SessionData.fromTokenData grantedData

            return GrantedSessionData (grantedData, sessionData)
        }

        let internal username currentApplication key token =
            token
            |> readSessionData currentApplication key
            |> Result.map (RawGrantedSessionData.sessionData >> _.Username >> Username)

        let authorize currentApplication: Authorize = fun appKey requiredPermission token -> result {
            let key = Symmetric appKey
            let! GrantedSessionData (grantedData, sessionData) = token |> readSessionData currentApplication key <@> JwtValidationError
            let! validData = requiredPermission |> JWT.validatePermissions grantedData

            return GrantedSessionData (validData, sessionData)
        }

        let create currentApp appKey customData sessionData =
            let currentInstance = currentApp |> Instance.concat "-"

            customData @ (sessionData |> SessionData.toCustomItems)
            |> GenericTokenData.CustomItems
            |> JWT.create (Issuer currentInstance) (Audience currentInstance) (Symmetric appKey)

        let renew: Renew = fun appKey (GrantedSessionData (JWT.GrantedTokenData (JWT.GrantedToken token, tokenData), sessionData)) -> result {
            use! key = Symmetric appKey |> JWTKey.writeKey

            let customData = (tokenData |> TokenData.toCustomItems) @ [
                CustomItem.String (UserCustomData.Username, sessionData.Username)
                CustomItem.String (UserCustomData.DisplayName, sessionData.DisplayName)
                CustomItem.Strings (UserCustomData.Groups, sessionData.Groups |> List.map PermissionGroup.value)
            ]

            return
                JwsDescriptor(
                    SigningKey = key,
                    JwtId = Guid.NewGuid().ToString(),
                    IssuedAt = token.IssuedAt,
                    NotBefore = token.NotBefore,
                    ExpirationTime = (DateTime.UtcNow.AddMinutes(30.0) |> Nullable),
                    Issuer = token.Issuer,
                    Audience = (token.Audiences |> Seq.head)
                )
                |> JWT.addCustomData customData
                |> JwtWriter().WriteTokenString
                |> JWT
                |> RenewedToken
        }

    [<RequireQualifiedAccess>]
    module internal RenewedSessionToken =
        let username currentApplication appKey (RenewedToken token) =
            token |> SessionJWT.username currentApplication (Symmetric appKey)
