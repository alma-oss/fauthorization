module Alma.Authorization.AmazonJWTTest

open Expecto

open Alma.ErrorHandling
open Alma.Authorization.Common
open Alma.Authorization
open Alma.Authorization.JWT
open Alma.Authorization.AmazonJWT
open Microsoft.Extensions.Logging
open Alma.ServiceIdentification

open JWTTest

let [<Literal>] ExpectedKid = "29bacf78-dbd1-4a06-8521-b4ecde2be36b"
let [<Literal>] Pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5c+nHYOAMPUwFMD0F2f2Cawcq+Df\n7TMvwhk6+o8+BMpwPYw5yt5nWtYAOZMJLuJIWPZGLiGPFjtNuq8keKxZew==\n-----END PUBLIC KEY-----"
let [<Literal>] Jwt = "eyJ0eXAiOiJKV1QiLCJraWQiOiIyOWJhY2Y3OC1kYmQxLTRhMDYtODUyMS1iNGVjZGUyYmUzNmIiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS8wMTQwN2Y3OS05NmFiLTQ2Y2ItYjQwMC1hZTYwNjJmNDQyOWEvdjIuMCIsImNsaWVudCI6IjNmMjYwOGM4LWZmOTUtNGZkOS1iMDg1LWJhOTgzMzZkNmQ4ZiIsInNpZ25lciI6ImFybjphd3M6ZWxhc3RpY2xvYWRiYWxhbmNpbmc6ZXUtd2VzdC0xOjgyMTE1MTYxMTE0Njpsb2FkYmFsYW5jZXIvYXBwL2RldjEtcHJpdmFjeS1jb21wb25lbnRzLXB1YmxpYy9mM2I1MDE4NzAwNGFlNDRlIiwiZXhwIjoxNzE3Njc0NTk3fQ==.eyJzdWIiOiItQ1JHWUZPUW9kQ2plX1RsaFZSbmVXVEk1TlpvSlhjVjkzRnR1bkN3Q2h3IiwibmFtZSI6IkNocm9tZWMgUGV0ciIsImZhbWlseV9uYW1lIjoiQ2hyb21lYyIsImdpdmVuX25hbWUiOiJQZXRyIiwicGljdHVyZSI6Imh0dHBzOi8vZ3JhcGgubWljcm9zb2Z0LmNvbS92MS4wL21lL3Bob3RvLyR2YWx1ZSIsImVtYWlsIjoicGV0ci5jaHJvbWVjQGFsbWFjYXJlZXIuY29tIiwiZXhwIjoxNzE3Njc0NTk3LCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vMDE0MDdmNzktOTZhYi00NmNiLWI0MDAtYWU2MDYyZjQ0MjlhL3YyLjAifQ==.tmTOb2fH12mxTd_oLRqlaIFLqt7Ppdlm6mkXMyGN8woZcbmtD_suUtJ92BRd3YJ48asmiAjlzuYHzB7V3828Sw=="

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

let instance (instance: string) = Create.Instance(instance) |> okOrFail

type JWTClientIdTestCase = {
    Description: string
    Token: string
    ValidateLifetime: bool
    Expected: Result<AmazonJWTClaims, AmazonJWTError>
}

let provideJWT = [
    {
        Description = "should read claims from token"
        Token = Jwt
        ValidateLifetime = false
        Expected = Ok {
            FirstName = "Petr"
            LastName = "Chromec"
            Name = "Chromec Petr"
            Email = "petr.chromec@almacareer.com"
        }
    }
    {
        Description = "should NOT read outdated token"
        Token = Jwt
        ValidateLifetime = true
        Expected = Error (JWTValidationFailed "IDX10223: Lifetime validation failed. The token is expired. ValidTo (UTC)")
    }
]

type LoginByOidcTestCase = {
    Description: string
    Token: string
    TokenKey: JWTKey
    CurrentApplication: Instance
    ValidateLifetime: bool
    Expected: Result<AmazonJWTClaims, AmazonJWTError>
}

let provideLogin = [
    {
        Description = "should login the user by oidc"
        Token = Jwt
        ValidateLifetime = false
        TokenKey = JWTKey.local "e081da7c-4151-49ea-9c2d-d57cdcf723a8"
        CurrentApplication = instance "prc-jwt-test-test"
        Expected = Ok {
            FirstName = "Petr"
            LastName = "Chromec"
            Name = "Chromec Petr"
            Email = "petr.chromec@almacareer.com"
        }
    }
]

[<Tests>]
let amazonJwtTest =
    testList "Authorization - Amazon JWT" [
        let dependencies =
            let region = "eu-west-1"
            {
                LoggerFactory = LoggerFactory.Create(ignore)
                HttpGet = function
                    | url when url.Contains(ExpectedKid) && url.Contains(region) -> AsyncResult.ofSuccess Pem
                    | _ -> AsyncResult.ofError "Invalid Kid"
                Region = region
                AzureTenantId = AzureTenantId.Default
                ExpectedAlbArn = "arn:aws:elasticloadbalancing:eu-west-1:821151611146:loadbalancer/app/dev1-privacy-components-public/f3b50187004ae44e"
                ValidateLifetime = false
            }

        yield!
            provideJWT
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let response =
                        tc.Token
                        |> JWT.read { dependencies with ValidateLifetime = tc.ValidateLifetime }
                        |> Async.RunSynchronously

                    match response, tc.Expected with
                    // error message contains a current timestamp, so just the prefix is checked
                    | Error (JWTValidationFailed error), Error (JWTValidationFailed expectedErrorPrefix) -> Expect.stringStarts error expectedErrorPrefix tc.Description
                    | response, expected -> Expect.equal expected response tc.Description
            )

        yield!
            provideLogin
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let response =
                        [
                            Authenticate.AmazonOidcDataHeader, tc.Token
                        ]
                        |> Authenticate.withOidcHeader tc.CurrentApplication tc.TokenKey { dependencies with ValidateLifetime = tc.ValidateLifetime }
                        |> Async.RunSynchronously

                    match response, tc.Expected with
                    | Ok oidcUser, Ok expected ->
                        Expect.equal expected oidcUser.Claims tc.Description

                        oidcUser.User.Token
                        |> validateJWT tc.CurrentApplication tc.TokenKey {
                            Description = tc.Description
                            CustomData = []
                            GroupItHas = None
                            GroupItHasNot = PermissionGroup "admin"
                            ExpectedUsername = oidcUser.Claims.Email
                            ExpectedDisplayName = oidcUser.Claims.Name
                            ExpectedClientId = None
                        }
                        |> ignore

                    | Error response, Error expected ->
                        Expect.equal expected response tc.Description

                    | response, expected ->
                        failtestf "Expected %A, but got %A" expected response
            )
    ]
