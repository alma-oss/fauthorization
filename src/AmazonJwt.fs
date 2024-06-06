namespace Alma.Authorization

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

    open Alma.ErrorHandling
    open Alma.ErrorHandling.AsyncResult.Operators
    open Alma.Authorization.Common

    /// For whole Alma, defined in CDK
    let [<Literal>] private DefaultAzureTenantId = "01407f79-96ab-46cb-b400-ae6062f4429a"

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

    [<RequireQualifiedAccess>]
    type AzureTenantId =
        | Custom of string
        | Default

    type ValidationDependencies = {
        LoggerFactory: ILoggerFactory
        HttpGet: string -> AsyncResult<string, string>
        ExpectedAlbArn: string
        /// Aws region, e.g. "us-west-2"
        Region: string
        AzureTenantId: AzureTenantId
        ValidateLifetime: bool
    }

    type AmazonJWTClaims = {
        FirstName: string
        LastName: string
        Name: string
        Email: string
    }

    type AmazonJWTError =
        | HttpError of string
        | JWTMissingSigner
        | JWTValidationFailed of string
        | JWTValidationError of exn
        | JWTError of exn

    type OidcUser = {
        User: User
        Claims: AmazonJWTClaims
    }

    [<RequireQualifiedAccess>]
    module JWT =
        let read dependencies (token: string) = asyncResult {
            //! uncomment for debugging
            //IdentityModelEventSource.ShowPII <- true
            //IdentityModelEventSource.LogCompleteSecurityArtifact <- true

            let logger = dependencies.LoggerFactory.CreateLogger("AmazonJWT")

            try
                let jwt = JsonWebToken(token)

                do!
                    match jwt.TryGetHeaderValue("signer") with
                    | true, (signer: string) ->
                        if signer = dependencies.ExpectedAlbArn then Ok ()
                        else Error (JWTValidationFailed $"Invalid signer: {signer}. Expected: {dependencies.ExpectedAlbArn}")
                    | _ -> Error JWTMissingSigner

                let url = $"https://public-keys.auth.elb.{dependencies.Region}.amazonaws.com/{jwt.Kid}"
                logger.LogDebug("Fetching public key from {url}", url)

                let! (publicRsa: string) = dependencies.HttpGet url <@> HttpError
                logger.LogDebug("Public key fetched: {publicRsa}", publicRsa)

                let key = convertPemToSecurityKey publicRsa
                key.KeyId <- jwt.Kid

                let azureTenantId =
                    match dependencies.AzureTenantId with
                    | AzureTenantId.Custom id -> id
                    | AzureTenantId.Default -> DefaultAzureTenantId

                let validationParameters =
                    new TokenValidationParameters(
                        // fsharplint:disable
                        RequireExpirationTime = true,
                        RequireSignedTokens = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = key,
                        ValidateAudience = false,
                        ValidateIssuer = true,
                        ValidIssuer = $"https://login.microsoftonline.com/{azureTenantId}/v2.0",
                        ValidateLifetime = dependencies.ValidateLifetime,
                        ClockSkew = TimeSpan.FromMinutes(2),
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
                    let claims = ClaimsPrincipal(identity)

                    let tryGetValue key =
                        claims.Claims
                        |> Seq.tryPick(fun claim -> if claim.Type = key then Some claim.Value else None)
                        |> Option.defaultValue ""

                    return {
                        FirstName = tryGetValue "given_name"
                        LastName = tryGetValue "family_name"
                        Name = tryGetValue "name"
                        Email = tryGetValue "email"
                    }

            with e -> return! Error (JWTError e)
        }

    [<RequireQualifiedAccess>]
    module Authenticate =
        open Alma.Authorization.JWT

        let [<Literal>] AmazonOidcDataHeader = "x-amzn-oidc-data"

        let withOidcHeader currentInstance tokenKey amazonDependencies headers = asyncResult {
            let! oidcJwt =
                headers
                |> List.tryPick (function
                    | AmazonOidcDataHeader, token -> Some token
                    | _ -> None
                )
                |> Result.ofOption (HttpError "Amazon JWT token not found in headers.")

            let! claims = oidcJwt |> JWT.read amazonDependencies

            return {
                Claims = claims
                User = {
                    Username = Username claims.Email
                    Token =
                        SymmetricJWT.create currentInstance tokenKey [
                            CustomItem.String (UserCustomData.Username, claims.Email)
                            CustomItem.String (UserCustomData.DisplayName, claims.Name)
                            CustomItem.Strings (UserCustomData.Groups, [])
                        ]
                }
            }
        }
