namespace Alma.Authorization

open System
open System.Text
open System.IdentityModel.Tokens.Jwt
open Alma.Authorization.Common

type Subject = Subject of string

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
    module JWTPart =
        open JsonWebToken
        open Feather.Cryptography.Encode

        type Header = Header of string
        type Payload = Payload of string
        type Signature = Signature of string

        type UnsignedJWT = UnsignedJWT of Header * Payload

        let internal unsignedPartFromDescriptor (descriptor: JwsDescriptor) =
            let base64 = Base64.encode >> Base64.toBase64Url
            let header = descriptor.Header.Serialize() |> base64 |> Header
            let payload = descriptor.Payload.Serialize() |> base64 |> Payload
            UnsignedJWT(header, payload)

        let unsignedJWTValue (UnsignedJWT (Header header, Payload payload)) =
            $"{header}.{payload}"

        let compose (header: string) (payload: string) (signature: string) =
            JWT $"{header}.{payload}.{signature}"

        let sign (unsignedJwt: UnsignedJWT) (Signature signature) =
            let unsignedValue = unsignedJWTValue unsignedJwt
            JWT $"{unsignedValue}.{signature}"

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
        | HasPayloadValue "client_id" (JWTValue.String clientId)
        | HasPayloadValue "client" (JWTValue.String clientId) -> Some (JWTClientId clientId)
        | _ -> None

    let (|HasUsername|_|) = function
        | HasPayloadValue UserCustomData.Username (JWTValue.String username) -> Some (Username username)
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

        type ExternalSigning = {
            Algorithm: string
            Sign: JWTPart.UnsignedJWT -> AsyncResult<JWTPart.Signature, string>
        }

        type JWTKey =
            | Symmetric of SymmetricJWTKey
            | Asymmetric of AsymmetricJWTKey
            | External of ExternalSigning

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
                | External { Algorithm = alg } ->
                    match alg.ToLower() with
                    | "hs256" -> SignatureAlgorithm.HmacSha256
                    | "rs256" -> SignatureAlgorithm.RsaSha256
                    | "es256" -> SignatureAlgorithm.EcdsaSha256
                    | _ -> failwithf "Unsupported external signing algorithm: %s" alg

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
                | External _ -> Error "External keys cannot be used for reading/validation"

            let internal writeKey = function
                | Symmetric symmetricKey -> symmetricKey |> Symmetric.toSymmetricJwk |> Ok
                | Asymmetric asymmetricKey -> asymmetricKey |> Asymmetric.toPrivateJwk |> Result.ofOption "Wrong key type, expected private key"
                | External _ -> Error "External keys handled separately in signing flow"

    type Issuer = Issuer of string
    type Audience = Audience of string
    type ExpiresIn =
        | ExpiresInMinutes of int

    type Requirement =
        | NotExpired
        | IssuedBy of Instance
        | IntendedFor of Instance

    type PermissionGroup = PermissionGroup of string

    type SessionData = {
        Username: Username
        DisplayName: string
        Groups: PermissionGroup list
        CustomClaims: CustomItem list
    }

    type TokenData = {
        Audience: Audience list
        Client: string option
        ClientId: string option
        DisplayName: string option
        Email: string option
        Expiration: DateTimeOffset option
        FamilyName: string option
        GivenName: string option
        Groups: PermissionGroup list
        Issuer: Issuer option
        Name: string option
        Picture: string option
        Scope: string option
        Subject: Subject option
        Username: string option
    }

    [<RequireQualifiedAccess>]
    type GenericTokenData =
        | TokenData of TokenData
        | CustomItems of CustomItem list
        | SessionData of SessionData

    [<RequireQualifiedAccess>]
    module PermissionGroup =
        let value (PermissionGroup group) = group

    type Permission =
        | ValidToken
        | Group of PermissionGroup
        | TokenData of (TokenData -> bool)

    [<RequireQualifiedAccess>]
    module internal SessionData =
        let toCustomItems { Username = Username username; DisplayName = displayName; Groups = groups; CustomClaims = custom } =
            let groupValues = groups |> List.map PermissionGroup.value

            [
                CustomItem.String (UserCustomData.Username, username)
                CustomItem.String (UserCustomData.DisplayName, displayName)
                match groupValues with
                | [] -> ()
                | _ -> CustomItem.Strings (UserCustomData.Groups, groupValues)

                yield! custom
            ]

    [<RequireQualifiedAccess>]
    module internal TokenData =
        let toCustomItems data =
            List.choose id [
                data.Username |> Option.map (fun u -> CustomItem.String (UserCustomData.Username, u))
                data.DisplayName |> Option.map (fun d -> CustomItem.String (UserCustomData.DisplayName, d))

                match data.Groups with
                | [] -> None
                | groups -> Some (CustomItem.Strings (UserCustomData.Groups, groups |> List.map PermissionGroup.value))

                data.Scope |> Option.map (fun s -> CustomItem.String ("scope", s))
                data.Subject |> Option.map (fun (Subject s) -> CustomItem.String ("sub", s))
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

        let getPayloadArrayValue (jwtResult: TokenValidationResult) (key: string) =
            match jwtResult.Token.Payload.TryGetValue(key) with
            | true, value ->
                match value.Value with
                | :? JwtArray as array ->
                    array
                    |> Seq.map (fun i -> i.Value.ToString())
                    |> Seq.toList
                | _ -> []
            | _ -> []

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
        type internal Renew = ExpiresIn -> JWTKey -> GrantedTokenData -> AsyncResult<RenewedToken, string>

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
                            Audience = getPayloadArrayValue jwtResult "aud" |> List.map Audience
                            Client = getHeaderValue jwtResult "client"
                            ClientId = getPayloadValue jwtResult "client_id"
                            DisplayName = getPayloadValue jwtResult UserCustomData.DisplayName
                            Email = getPayloadValue jwtResult "email"
                            Expiration = getDateTimeOffset jwtResult "exp"
                            FamilyName = getPayloadValue jwtResult "family_name"
                            GivenName = getPayloadValue jwtResult "given_name"
                            Groups = getGroups jwtResult UserCustomData.Groups
                            Issuer = getPayloadValue jwtResult "iss" |> Option.map Issuer
                            Name = getPayloadValue jwtResult "name"
                            Picture = getPayloadValue jwtResult "picture"
                            Scope = getPayloadValue jwtResult "scope"
                            Subject = getPayloadValue jwtResult "sub" |> Option.map Subject
                            Username = getPayloadValue jwtResult UserCustomData.Username
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

        let private createDescriptor (Issuer issuer) (Audience audience) (ExpiresInMinutes expiresInMinutes) jwtKey customData key =
            let now = DateTime.UtcNow

            let customData =
                match customData with
                | GenericTokenData.TokenData data -> TokenData.toCustomItems data
                | GenericTokenData.CustomItems items -> items
                | GenericTokenData.SessionData data -> SessionData.toCustomItems data

            let descriptor = JwsDescriptor(
                Type = "JWT",
                Algorithm = JWTKey.signatureAlgorithm jwtKey,
                JwtId = Guid.NewGuid().ToString(),
                IssuedAt = (now |> Nullable),
                NotBefore = (now |> Nullable),
                ExpirationTime = (now.AddMinutes(expiresInMinutes) |> Nullable),
                Issuer = issuer,
                Audience = audience
            )

            match key with
            | Some key -> descriptor.SigningKey <- key
            | None -> ()

            descriptor |> addCustomData customData


        let create iss aud exp (jwtKey: JWTKey) customData = asyncResult {
            let createDescriptor = createDescriptor iss aud exp jwtKey customData

            match jwtKey with
            | External sign ->
                let unsignedJwt =
                    createDescriptor None
                    |> JWTPart.unsignedPartFromDescriptor

                let! signature = sign.Sign unsignedJwt

                return JWTPart.sign unsignedJwt signature
            | _ ->
                use! key = jwtKey |> JWTKey.writeKey
                let descriptor =  createDescriptor (Some key)

                return
                    descriptor
                    |> JwtWriter().WriteTokenString
                    |> JWT
        }

        let renew: Renew = fun (ExpiresInMinutes expiresIn) jwtKey (GrantedTokenData (GrantedToken token, tokenData)) -> asyncResult {
            let createDescriptor key =
                let descriptor = JwsDescriptor(
                    Type = "JWT",
                    Algorithm = JWTKey.signatureAlgorithm jwtKey,
                    JwtId = Guid.NewGuid().ToString(),
                    IssuedAt = token.IssuedAt,
                    NotBefore = token.NotBefore,
                    ExpirationTime = (DateTime.UtcNow.AddMinutes(expiresIn) |> Nullable),
                    Issuer = token.Issuer,
                    Audience = (token.Audiences |> Seq.head)
                )

                match key with
                | Some key -> descriptor.SigningKey <- key
                | None -> ()

                descriptor
                |> addCustomData (tokenData |> TokenData.toCustomItems)

            match jwtKey with
            | External sign ->
                let unsignedJwt =
                    createDescriptor None
                    |> JWTPart.unsignedPartFromDescriptor

                let! signature = sign.Sign unsignedJwt

                return JWTPart.sign unsignedJwt signature |> RenewedToken
            | _ ->
                use! key = jwtKey |> JWTKey.writeKey
                let descriptor =  createDescriptor (Some key)

                return
                    descriptor
                    |> JwtWriter().WriteTokenString
                    |> JWT
                    |> RenewedToken
        }

    [<RequireQualifiedAccess>]
    module SessionJWT =
        type GrantedSessionData = private GrantedSessionData of SessionData * JWT.GrantedTokenData

        let sessionData (GrantedSessionData (sessionData, _)) = sessionData

        let create currentInstance jwtKey sessionData =
            let currentApplication = currentInstance |> Instance.concat "-"

            GenericTokenData.SessionData sessionData
            |> JWT.create
                (Issuer currentApplication)
                (Audience currentApplication)
                (ExpiresInMinutes 30)
                jwtKey

        let private validateSessionData grantedData = result {
            let tokenData = grantedData |> JWT.tokenData
            let! username = tokenData.Username |> Result.ofOption MissingUsername
            let! displayName = tokenData.DisplayName |> Result.ofOption MissingDisplayName

            let! groups =
                match tokenData.Groups with
                | [] -> Error MissingGroups
                | groups -> Ok groups

            return {
                Username = Username username
                DisplayName = displayName
                Groups = groups
                CustomClaims = tokenData |> TokenData.toCustomItems // todo - filter out data already in session data
            }
        }

        let authorize currentInstance jwtKey permission jwt = result {
            let! grantedTokenData =
                jwt
                |> JWT.authorize
                    [
                        NotExpired
                        IssuedBy currentInstance
                        IntendedFor currentInstance
                    ]
                    jwtKey
                    permission

            let! sessionData =
                grantedTokenData
                |> validateSessionData
                |> Result.mapError JwtValidationError

            return GrantedSessionData (sessionData, grantedTokenData)
        }

        let renew jwtKey (GrantedSessionData (_, grantedTokenData)) =
            grantedTokenData
            |> JWT.renew (ExpiresInMinutes 30) jwtKey
