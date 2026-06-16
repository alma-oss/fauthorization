# Examples

All code for this skill lives here. Examples are ordered by increasing complexity and each is
self-contained. Placeholders (`ServiceA`, `WebApi`, `Worker`, etc.) are neutral by design.

## Basic Example — Create a token and read claims

```fsharp
open Alma.ServiceIdentification
open Alma.Authorization
open Alma.Authorization.JWT
open Alma.Authorization.Common
open Feather.ErrorHandling

// A deterministic symmetric key (load from config/secret in production).
let jwtKey =
    JWTKey.Symmetric.tryParse "edbe2f5a-4d4a-4975-98b6-b794532e9732"
    |> Option.map Symmetric
    |> Option.defaultWith (fun () -> failwith "invalid key")

let sessionData = {
    Username = Username "service-a"
    DisplayName = "Service A"
    Groups = [ PermissionGroup "worker" ]
    CustomClaims = [ CustomItem.String ("client_id", "client-123") ]
}

// Create a raw JWT for ServiceA -> WebApi.
let createToken () = asyncResult {
    return!
        GenericTokenData.SessionData sessionData
        |> JWT.create (Issuer "service-a") (Audience "web-api") (ExpiresInMinutes 30) jwtKey
}

// Read claims from an incoming header map using active patterns.
let readClientId (headers: Map<string, string>) =
    match headers with
    | JWT.HasJWTAuthorization (JWT.HasClientId (JWT.JWTClientId clientId)) -> Some clientId
    | _ -> None
```

## Realistic Example — SessionJWT create / authorize / renew

```fsharp
open Alma.ServiceIdentification
open Alma.Authorization
open Alma.Authorization.JWT
open Alma.Authorization.Common
open Feather.ErrorHandling

let currentInstance = Create.Instance "prc-web-api-stable" |> Result.defaultWith failwith
let jwtKey = JWTKey.Symmetric.generate () |> Symmetric

let session = {
    Username = Username "service-a"
    DisplayName = "Service A"
    Groups = [ PermissionGroup "worker" ]
    CustomClaims = []
}

let flow () = asyncResult {
    // Issue: issuer = audience = current instance, 30 min default lifetime.
    let! (Common.JWT _ as token) = SessionJWT.create currentInstance jwtKey session

    // Validate: NotExpired + IssuedBy + IntendedFor applied automatically.
    let granted =
        token
        |> SessionJWT.authorize currentInstance jwtKey ValidToken
        |> Result.defaultWith (fun e -> failwithf "%A" e)

    // Renew: slide the session forward.
    let! (RenewedToken renewed) = SessionJWT.renew jwtKey granted
    return renewed
}
```

## Integration Example — Casbin RBAC enforcement

```fsharp
open Alma.Authorization
open Alma.Authorization.Session

let enforcer =
    Authorization.createEnforcer Model.RBAC (Policy.PolicyFilePath "policy.csv")
    |> Result.defaultWith (fun e -> failwith (EnforcerCreationError.format e))

// Direct enforcement of an "object:capability" scope for a subject.
let canRead =
    Scope.parse "data:read"
    |> Result.map (fun scope -> Authorization.enforce enforcer scope (Subject "service-a"))

// Turn an enforcer into an EnforceScope for the session layer.
let enforceScope =
    EnforceScope.prepare enforcer (fun tokenData ->
        tokenData.Username |> Option.defaultValue "anonymous" |> Subject
    )
```

## Securing an API Endpoint — the `>?>` operator

```fsharp
open Shared
open Feather.ErrorHandling
open Alma.Authorization
open Alma.Authorization.Common
open Alma.Authorization.Session

type ApiError = ApiError of string

// One Authorization record per app: read key + renew key + current instance.
let authorization = {
    CurrentApplication = currentInstance
    AuthorizedBy = jwtKey
    KeyForRenewToken = jwtKey
}

let logError (message: string) = eprintfn "%s" message

// Build the operators once.
let inline private (>?>) authorize action =
    Authorize.authorizeAction authorization ApiError logError authorize (Authorize.Action.Request action)

let private (>?>>) authorize action =
    Authorize.authorizeAction authorization ApiError logError authorize
        (Authorize.Action.RequestWithUsername action)

let api = {
    // Any valid session.
    LoadGenericData = Authorize.withLogin >?> fun () -> asyncResult {
        return! Worker.loadData () <@> (string >> ApiError)
    }

    // Scope check; the authenticated Username is passed to the action.
    LoadScopedData =
        Authorize.withScope enforceScope (Scope.parse "data:read" |> Result.defaultWith failwith)
        >?>> fun (username: Username) () -> asyncResult {
            return! Worker.loadFor username <@> (string >> ApiError)
        }
}
```

## External Signing — delegate signing to an external service

```fsharp
open Feather.ErrorHandling
open Alma.Authorization
open Alma.Authorization.JWT

// `Sign` receives the unsigned header.payload and returns a signature.
let externalKey = JWTKey.External {
    Algorithm = "RS256"   // RS256 | ES256 | HS256
    Sign = fun unsignedJwt -> asyncResult {
        let! signature =
            unsignedJwt
            |> JWTPart.unsignedJWTValue
            |> ExternalSigner.sign        // neutral placeholder for a remote signing API
        return JWTPart.Signature signature
    }
}

let signWithExternal tokenData = asyncResult {
    return!
        GenericTokenData.TokenData tokenData
        |> JWT.create (Issuer "service-a") (Audience "web-api") (ExpiresInMinutes 15) externalKey
}
```

## Amazon ALB Validation — validate an OIDC header

```fsharp
open Alma.ServiceIdentification
open Alma.Authorization.JWT
open Alma.Authorization.AWS
open Feather.ErrorHandling

let dependencies: AmazonJWT.ValidationDependencies = {
    LoggerFactory = loggerFactory
    HttpGet = fun url -> asyncResult { return! Http.getString url }   // neutral HTTP getter
    ExpectedAlbArn = "arn:aws:elasticloadbalancing:us-west-2:000000000000:loadbalancer/app/demo"
    Region = "us-west-2"
    Issuer = Issuer "https://example.test"
    ValidateLifetime = true
}

// Read and validate a raw ALB token into TokenData.
let readAlbToken token = AmazonJWT.JWT.read dependencies token

// Or read the x-amzn-oidc-data header and mint a SessionJWT in one step.
let authenticate currentInstance tokenKey headers =
    AmazonJWT.Authenticate.withOidcHeader currentInstance tokenKey dependencies headers
```

## Expecto Round-Trip Test

```fsharp
open Expecto
open Alma.ServiceIdentification
open Alma.Authorization
open Alma.Authorization.JWT
open Alma.Authorization.Common

let okOrFail = function Ok x -> x | Error e -> failtestf "%A" e

[<Tests>]
let tests =
    testCase "session token survives renewal" <| fun _ ->
        let instance = Create.Instance "prc-web-api-test" |> okOrFail
        let key =
            JWTKey.Symmetric.tryParse "482caea0-4162-4fcd-9a29-94fd77477f7d"
            |> Option.get |> Symmetric

        let session = {
            Username = Username "service-a"
            DisplayName = "Service A"
            Groups = [ PermissionGroup "worker" ]
            CustomClaims = []
        }

        let token = SessionJWT.create instance key session |> Async.RunSynchronously |> okOrFail
        let granted = token |> SessionJWT.authorize instance key (Group (PermissionGroup "worker"))
        Expect.isOk granted "worker group should be granted"
```
