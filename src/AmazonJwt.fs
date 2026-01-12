namespace Alma.Authorization.AWS

/// Inspired by:
/// https://github.com/awslabs/aws-alb-identity-aspnetcore/blob/master/Amazon.ApplicationLoadBalancer.Identity.AspNetCore/ALBIdentityMiddleware.cs
module AmazonJWT =
    open System
    open System.IO
    open System.Security.Claims
    open System.Security.Cryptography
    open Microsoft.Extensions.Logging
    open Microsoft.IdentityModel.JsonWebTokens
    open Microsoft.IdentityModel.Tokens
    open Org.BouncyCastle.Crypto.Parameters
    open Org.BouncyCastle.OpenSsl

    open Alma.Authorization.Common
    open Alma.Authorization.JWT

    open Feather.ErrorHandling
    open Feather.ErrorHandling.AsyncResult.Operators

    let private convertPemToSecurityKey pem =
        // fsharplint:disable-next-line
        use publicKeyTextReader = new StringReader(pem)
        let ec = PemReader(publicKeyTextReader) |> _.ReadObject() :?> ECPublicKeyParameters
        let ecParameters =
            ECParameters(
                Curve = ECCurve.NamedCurves.nistP256,
                Q = ECPoint(
                    X = ec.Q.XCoord.GetEncoded(),
                    Y = ec.Q.YCoord.GetEncoded()
                )
            )

        ECDsa.Create(ecParameters) |> ECDsaSecurityKey

    type ValidationDependencies = {
        LoggerFactory: ILoggerFactory
        HttpGet: string -> AsyncResult<string, string>
        ExpectedAlbArn: string
        /// Aws region, e.g. "us-west-2"
        Region: string
        Issuer: Issuer
        ValidateLifetime: bool
    }

    type AmazonJWTError =
        | HttpError of string
        | JWTCreationError of string
        | JWTMissingSigner
        | JWTValidationFailed of string
        | JWTValidationError of exn
        | JWTError of exn

    type OidcUser = {
        User: User
        TokenData: TokenData
    }

    [<RequireQualifiedAccess>]
    module JWT =
        let read dependencies (token: string): AsyncResult<TokenData, AmazonJWTError> = asyncResult {
            //! uncomment for debugging
            //IdentityModelEventSource.ShowPII <- true
            //IdentityModelEventSource.LogCompleteSecurityArtifact <- true

            let logger = dependencies.LoggerFactory.CreateLogger("AmazonJWT")

            try
                let jwt = JsonWebToken(token)

                let tryGetHeaderValue (key: string) =
                    match jwt.TryGetHeaderValue(key) with
                    | true, value -> Some value
                    | _ -> None

                do!
                    match tryGetHeaderValue "signer" with
                    | Some signer when signer = dependencies.ExpectedAlbArn -> Ok ()
                    | Some invalid -> Error (JWTValidationFailed $"Invalid signer: {invalid}. Expected: {dependencies.ExpectedAlbArn}")
                    | _ -> Error JWTMissingSigner

                let url = $"https://public-keys.auth.elb.{dependencies.Region}.amazonaws.com/{jwt.Kid}"
                logger.LogDebug("Fetching public key from {url}", url)

                let! (publicRsa: string) = dependencies.HttpGet url <@> HttpError
                logger.LogDebug("Public key fetched: {publicRsa}", publicRsa)

                let key = convertPemToSecurityKey publicRsa
                key.KeyId <- jwt.Kid

                let (Issuer requiredIssuer) = dependencies.Issuer

                let validationParameters =
                    new TokenValidationParameters(
                        // fsharplint:disable
                        RequireExpirationTime = true,
                        RequireSignedTokens = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = key,
                        ValidateAudience = false,
                        ValidateIssuer = true,
                        ValidIssuer = requiredIssuer,
                        ValidateLifetime = dependencies.ValidateLifetime,
                        ClockSkew = TimeSpan.FromMinutes(int64 2),
                        ValidAlgorithms = [ SecurityAlgorithms.EcdsaSha256 ]
                        // fsharplint:enable
                    )

                let! (validationResult: TokenValidationResult) =
                    JsonWebTokenHandler().ValidateTokenAsync(jwt.EncodedToken, validationParameters)
                    |> AsyncResult.ofTaskCatch JWTValidationError

                if not validationResult.IsValid then
                    return! Error (JWTValidationFailed validationResult.Exception.Message)
                else
                    let identity = ClaimsIdentity(jwt.Claims, "oidc")
                    let claims = ClaimsPrincipal identity

                    let tryGetValue key =
                        claims.Claims
                        |> Seq.tryPick(fun claim -> if claim.Type = key then Some claim.Value else None)

                    return {
                        Username = tryGetValue UserCustomData.Username
                        DisplayName = tryGetValue UserCustomData.DisplayName
                        Groups = []
                        Scope = tryGetValue "scope"
                        Issuer = tryGetValue "iss"
                        Expiration = tryGetValue "exp" |> Option.bind tryParseDateTimeOffset
                        ClientId = tryGetValue "client_id"
                        Name = tryGetValue "name"
                        FamilyName = tryGetValue "family_name"
                        GivenName = tryGetValue "given_name"
                        Picture = tryGetValue "picture"
                        Email = tryGetValue "email"
                        Client = tryGetHeaderValue "client"
                    }

            with e -> return! Error (JWTError e)
        }

    [<RequireQualifiedAccess>]
    module Authenticate =
        let [<Literal>] AmazonOidcDataHeader = "x-amzn-oidc-data"

        let withOidcHeader currentInstance tokenKey amazonDependencies headers = asyncResult {
            let! oidcJwt =
                headers
                |> List.tryPick (function
                    | AmazonOidcDataHeader, token -> Some token
                    | _ -> None
                )
                |> Result.ofOption (HttpError "Amazon JWT token not found in headers.")

            let! (claims: TokenData) = oidcJwt |> JWT.read amazonDependencies

            let! userName =
                claims.Username
                |> Option.orElse claims.Email
                |> Result.ofOption (JWTValidationFailed "Username and Email claims are missing.")

            let displayName =
                claims.DisplayName
                |> Option.orElse claims.Name
                |> Option.defaultValue userName

            let! token =
                SessionJWT.create currentInstance tokenKey (List.choose id [
                    claims.ClientId
                    |> Option.orElse claims.Client
                    |> Option.map (fun clientId -> CustomItem.String ("client_id", clientId))
                ]) {
                    Username = userName
                    DisplayName = displayName
                    Groups = [ PermissionGroup AmazonOidcDataHeader ]
                }
                |> Result.mapError JWTCreationError

            return {
                TokenData = claims
                User = {
                    Username = Username userName
                    Token = token
                }
            }
        }
