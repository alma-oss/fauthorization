module Alma.Authorization.JWTTest

open Expecto

open System
open System.IO
open System.Net
open Alma.ServiceIdentification
open Alma.Authorization
open Alma.Authorization.JWT
open Alma.Authorization.Common
open Feather.ErrorHandling

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

let runOkOrFail = Async.RunSynchronously >> okOrFail

let instance (instance: string) = Create.Instance(instance) |> okOrFail
let publicRSAKey pemName =
    let pemPath = Path.Combine("Fixtures", pemName)

    {
        Pem = File.ReadAllText(pemPath)
        Algorithm = Rsa
    }
    |> PublicPem
    |> Public
    |> Asymmetric

type Validation = {
    Key: JWTKey
    Requirements: Requirement list
    ExpectedResult: Result<TokenData, JWT.AuthorizationError>
}

type JWTClientIdTestCase = {
    Description: string
    Headers: Map<string, string>
    /// If passed, jwt must be valid by this key
    ShouldBeValid: Validation option
    Expected: string option
}

let provideJWTClientId = [
    {
        Description = "should find a client_id in JWT payload"
        Headers =
            [
                "Authorization", "Bearer eyJraWQiOiJiOGNlZGJkMi01YmZjLTRiZTktOGY2Yy0yNWQxMzFmNGFmN2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NmUwZDg0ZC01N2RlLTRkYzktYWNlNy1lNmE2NTdlMTczY2QiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImRvbWFpbi1jb250ZXh0LXB1cnBvc2UtdmVyc2lvbi9iYXNpYy5yZWFkIiwiYXV0aF90aW1lIjoxNzA2NTMyNzkyLCJpc3MiOiJodHRwczovL2F1dGguc3ZjIiwiZXhwIjoxNzA2NjE5MTkyLCJpYXQiOjE3MDY1MzI3OTIsInZlcnNpb24iOjIsImp0aSI6ImIwMjkxNjRmLWEzMjUtNDc3ZS1iNWEyLTljNGViMGM2MGUzZSIsImNsaWVudF9pZCI6Ijc2ZTBkODRkLTU3ZGUtNGRjOS1hY2U3LWU2YTY1N2UxNzNjZCJ9.uhJHoqxf8Ef-ip5vg3T3l-v_NZiGh6W4x5AXkqnYssCX1NTL4Kw-auWOsR71YSoB5db8UPkItVRpeOr-Sx1_1EY4RQe3o3Vo3ssfOdddvV3VExexdH2e7HEOXb2YS0U335mg2tbReQT1dZWQwaGmq8lXRAokCTYSHt0g96zpImCxnI-C17J4InTVr8sc7bEKMvhNdSWEPWFoFLOjfmQ6xP-ebRqWchlkKZK5jYZs-lQLJ7xecmzm1Xx3K-PPeYJWuzS3GNwBYEFVj7W_MSycs6M8GMPljBOn0kPVAGXoyh9GaTwzqWBUfxQuKeUYip9lIYBXTzg0NqVko6h9njQZig"
            ]
            |> Map.ofList
        ShouldBeValid = Some {
            Key = publicRSAKey "test-public-key.pem"
            Requirements = []
            ExpectedResult = Ok {
                Audience = []
                Client = None
                ClientId = Some "76e0d84d-57de-4dc9-ace7-e6a657e173cd"
                DisplayName = None
                Email = None
                Expiration = Some (DateTimeOffset.FromUnixTimeSeconds 1706619192L)
                FamilyName = None
                GivenName = None
                Groups = []
                Issuer = Some (Issuer "https://auth.svc")
                Name = None
                Picture = None
                Scope = Some "domain-context-purpose-version/basic.read"
                Subject = Some (Subject "76e0d84d-57de-4dc9-ace7-e6a657e173cd")
                Username = None
            }
        }
        Expected = Some "76e0d84d-57de-4dc9-ace7-e6a657e173cd"
    }
    {
        Description = "should find client id but fail on expiration"
        Headers =
            [
                "Authorization", "Bearer eyJraWQiOiJiOGNlZGJkMi01YmZjLTRiZTktOGY2Yy0yNWQxMzFmNGFmN2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI3NmUwZDg0ZC01N2RlLTRkYzktYWNlNy1lNmE2NTdlMTczY2QiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImRvbWFpbi1jb250ZXh0LXB1cnBvc2UtdmVyc2lvbi9iYXNpYy5yZWFkIiwiYXV0aF90aW1lIjoxNzA2NTMyNzkyLCJpc3MiOiJodHRwczovL2F1dGguc3ZjIiwiZXhwIjoxNzA2NjE5MTkyLCJpYXQiOjE3MDY1MzI3OTIsInZlcnNpb24iOjIsImp0aSI6ImIwMjkxNjRmLWEzMjUtNDc3ZS1iNWEyLTljNGViMGM2MGUzZSIsImNsaWVudF9pZCI6Ijc2ZTBkODRkLTU3ZGUtNGRjOS1hY2U3LWU2YTY1N2UxNzNjZCJ9.uhJHoqxf8Ef-ip5vg3T3l-v_NZiGh6W4x5AXkqnYssCX1NTL4Kw-auWOsR71YSoB5db8UPkItVRpeOr-Sx1_1EY4RQe3o3Vo3ssfOdddvV3VExexdH2e7HEOXb2YS0U335mg2tbReQT1dZWQwaGmq8lXRAokCTYSHt0g96zpImCxnI-C17J4InTVr8sc7bEKMvhNdSWEPWFoFLOjfmQ6xP-ebRqWchlkKZK5jYZs-lQLJ7xecmzm1Xx3K-PPeYJWuzS3GNwBYEFVj7W_MSycs6M8GMPljBOn0kPVAGXoyh9GaTwzqWBUfxQuKeUYip9lIYBXTzg0NqVko6h9njQZig"
            ]
            |> Map.ofList
        ShouldBeValid = Some {
            Key = publicRSAKey "test-public-key.pem"
            Requirements = [ NotExpired ]
            ExpectedResult = Error (JwtValidationError (TokenStatus "Expired"))
        }
        Expected = Some "76e0d84d-57de-4dc9-ace7-e6a657e173cd"
    }
    {
        Description = "should NOT find a client_id in invalid JWT payload"
        Headers =
            [
                "Authorization", "Bearer token.token.token"
            ]
            |> Map.ofList
        ShouldBeValid = None
        Expected = None
    }
]

type JWTSessionTokenTestCase = {
    Description: string
    SessionData: SessionData
    GroupItHas: PermissionGroup option
    GroupItHasNot: PermissionGroup
    ExpectedUsername: Username
    ExpectedDisplayName: string
    ExpectedClientId: string option
}

let provideJWTSessionToken = [
    {
        Description = "should create symmetric admin token"
        SessionData =
            {
                Username = Username "admin"
                DisplayName = "administrátor"
                Groups = [ PermissionGroup "local" ]
                CustomClaims = [
                    CustomItem.String ("client_id", "admin-client-id")
                ]
            }
        GroupItHas = PermissionGroup "local" |> Some
        GroupItHasNot = PermissionGroup "admin"
        ExpectedUsername = Username "admin"
        ExpectedDisplayName = "administrátor"
        ExpectedClientId = Some "admin-client-id"
    }
    {
        Description = "should create symmetric user token"
        SessionData =
            {
                Username = Username "prijmenij"
                DisplayName = "Jméno Příjmení"
                Groups = [ PermissionGroup "user"; PermissionGroup "team-member" ]
                CustomClaims = []
            }
        GroupItHas = PermissionGroup "team-member" |> Some
        GroupItHasNot = PermissionGroup "local"
        ExpectedUsername = Username "prijmenij"
        ExpectedDisplayName = "Jméno Příjmení"
        ExpectedClientId = None
    }
]

let validateSessionJWT currentInstance tokenKey tc (Common.JWT jwt as token) =
    let isJWT =
        match jwt with
        | JWT.IsJWT _ -> true
        | _ -> false
    Expect.isTrue isJWT tc.Description

    let clientId =
        match JWT.Raw token with
        | JWT.HasClientId (JWT.JWTClientId clientId) -> Some clientId
        | _ -> None
    Expect.equal clientId tc.ExpectedClientId tc.Description

    let username =
        match JWT.Raw token with
        | JWT.HasUsername username -> username
        | _ -> failtestf "Username not found in JWT token."
    Expect.equal username tc.ExpectedUsername tc.Description

    let displayName =
        match JWT.Raw token with
        | JWT.HasDisplayName displayName -> displayName
        | _ -> failtestf "DisplayName not found in JWT token."
    Expect.equal displayName tc.ExpectedDisplayName tc.Description

    let isGranted = token |> SessionJWT.authorize currentInstance tokenKey ValidToken
    Expect.isOk isGranted tc.Description

    match tc.GroupItHas with
    | Some expectedGroup ->
        let isGrantedByGroup = token |> SessionJWT.authorize currentInstance tokenKey (Group expectedGroup)
        Expect.isOk isGrantedByGroup tc.Description
    | _ -> ()

    let isNotGrantedByGroup = token |> SessionJWT.authorize currentInstance tokenKey (Group tc.GroupItHasNot)
    Expect.equal isNotGrantedByGroup (Error (ActionIsNotGranted "You are not authorized for this action.")) tc.Description

    isGranted |> okOrFail

let assertValidJWT (validation: Validation) (tc: JWTClientIdTestCase) (token: Alma.Authorization.JWT) =
    let tokenData =
        token.Common
        |> JWT.authorize validation.Requirements validation.Key ValidToken
        |> Result.map JWT.tokenData

    Expect.equal tokenData validation.ExpectedResult tc.Description

[<Tests>]
let jwtTest =
    testList "Authorization - JWT" [
        yield!
            provideJWTClientId
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let client =
                        match tc.Headers with
                        | JWT.HasJWTAuthorization (JWT.HasClientId (JWT.JWTClientId clientId) as jwt) ->
                            match tc.ShouldBeValid with
                            | Some validation -> jwt |> assertValidJWT validation tc
                            | None -> ()

                            Some clientId
                        | _ -> None

                    Expect.equal tc.Expected client tc.Description
            )

        yield!
            provideJWTSessionToken
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let currentInstance = instance "prc-jwt-test-test"
                    let appKey = JWTKey.Symmetric.tryParse "edbe2f5a-4d4a-4975-98b6-b794532e9732" |> Result.ofOption "Invalid Key" |> okOrFail
                    let jwtKey = Symmetric appKey

                    let token =
                        tc.SessionData
                        |> SessionJWT.create currentInstance jwtKey
                        |> Async.RunSynchronously
                        |> okOrFail

                    let grantedSessionData = token |> validateSessionJWT currentInstance jwtKey tc
                    let (RenewedToken renewedToken) = grantedSessionData |> SessionJWT.renew jwtKey |> runOkOrFail

                    renewedToken
                    |> validateSessionJWT currentInstance jwtKey {
                        tc with Description = tc.Description + " - renewed"
                    }
                    |> ignore
            )
    ]
