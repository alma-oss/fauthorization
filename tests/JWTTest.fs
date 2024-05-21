module Alma.Authorization.JWTTest

open Expecto

open System.IO
open System.Net
open Alma.ServiceIdentification
open Alma.Authorization
open Alma.Authorization.JWT

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

let instance (instance: string) = Create.Instance(instance) |> okOrFail

type JWTClientIdTestCase = {
    Description: string
    Headers: Map<string, string>
    Expected: string option
}

let provideJWTClientId = [
    {
        Description = "should find a client_id in JWT payload"
        Headers =
            [
                "Authorization", "Bearer eyJraWQiOiIzVUlSUEZsaklCNkxnYnJ2aEd6cEFOVjhkalI4N3VmUHY0Z1k2XC9rbjJEUT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2bXA0Z3M4ODJyY2RtYWVoMDAxY281ZXJxZCIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiY29uc2VudHMtYWNsSW50ZXJhY3Rpb25FbnRyeS1kZXYtc3RhYmxlXC9iYXNpYy5yZWFkIiwiYXV0aF90aW1lIjoxNzA2NTMyNzkyLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb21cL2V1LXdlc3QtMV9iVGJLbG9nb0wiLCJleHAiOjE3MDY2MTkxOTIsImlhdCI6MTcwNjUzMjc5MiwidmVyc2lvbiI6MiwianRpIjoiOGU1YjAyYzktMWIxMi00NWU1LWIzYTYtMDA5MzUzNTU5OTk0IiwiY2xpZW50X2lkIjoiNm1wNGdzODgycmNkbWFlaDAwMWNvNWVycWQifQ.aUWk5niUUAWLDzO4AnPHhtf3btX4Mpgup2w0EHf5l8HZSPAkECNTBprQLndjgz4smbNg26QM5KiIyHHiuhr3xOh84MW6orPz03344dx2-ARCSrjVm2Ix2bugDcsE6rXkCkjkuxixc5IOWMIni_bE1AOrGpfEt_k66c79Src2qnxu817RSlDtFrjiZSm8z5z0pwWLJzYCRwtljch8-KmIWIbUBRaVtlsKBQDq6oP8NfqeHgbHTFCeaU721aq5ZNkGWR0tP1PYg0JZwQPj0uPcFtfB6Q5CMlgqwjvAX_ZFOvzWo5QTqf85K_vyH15NQaGqeNzRP6FrtdxIC_qj9DmaKg"
            ]
            |> Map.ofList
        Expected = Some "6mp4gs882rcdmaeh001co5erqd"
    }
    {
        Description = "should NOT find a client_id in invalid JWT payload"
        Headers =
            [
                "Authorization", "Bearer token.token.token"
            ]
            |> Map.ofList
        Expected = None
    }
]

type JWTCreateTokenTestCase = {
    Description: string
    CustomData: CustomItem list
    GroupItHas: PermissionGroup
    GroupItHasNot: PermissionGroup
    ExpectedUsername: string
    ExpectedDisplayName: string
    ExpectedClientId: string option
}

let provideJWTSymmetricToken = [
    {
        Description = "should create symmetric admin token"
        CustomData = [
            CustomItem.String (UserCustomData.Username, "admin")
            CustomItem.String (UserCustomData.DisplayName, "administrátor")
            CustomItem.Strings (UserCustomData.Groups, [ "local" ])
            CustomItem.String ("client_id", "admin-client-id")
        ]
        GroupItHas = PermissionGroup "local"
        GroupItHasNot = PermissionGroup "admin"
        ExpectedUsername = "admin"
        ExpectedDisplayName = "administrátor"
        ExpectedClientId = Some "admin-client-id"
    }
    {
        Description = "should create symmetric user token"
        CustomData = [
            CustomItem.String (UserCustomData.Username, "prijmenij")
            CustomItem.String (UserCustomData.DisplayName, "Jméno Příjmení")
            CustomItem.Strings (UserCustomData.Groups, [ "user"; "team-member" ])
        ]
        GroupItHas = PermissionGroup "team-member"
        GroupItHasNot = PermissionGroup "local"
        ExpectedUsername = "prijmenij"
        ExpectedDisplayName = "Jméno Příjmení"
        ExpectedClientId = None
    }
]

let private validateJWT currentInstance tokenKey tc token =
    let isJWT =
        match token |> SymmetricJWT.value with
        | JWT.IsJWT _ -> true
        | _ -> false
    Expect.isTrue isJWT tc.Description

    let clientId =
        match JWT.Raw token with
        | JWT.HasClientId (JWT.JWTClientId clientId) -> Some clientId
        | _ -> None
    Expect.equal tc.ExpectedClientId clientId tc.Description

    let username =
        match JWT.Raw token with
        | JWT.HasUsername username -> username
        | _ -> failtestf "Username not found in JWT token."
    Expect.equal tc.ExpectedUsername username tc.Description

    let displayName =
        match JWT.Raw token with
        | JWT.HasDisplayName displayName -> displayName
        | _ -> failtestf "DisplayName not found in JWT token."
    Expect.equal tc.ExpectedDisplayName displayName tc.Description

    let isGranted = ValidToken |> SymmetricJWT.isGranted currentInstance [ tokenKey ] token
    Expect.isOk isGranted tc.Description

    let isGrantedByGroup = Group tc.GroupItHas |> SymmetricJWT.isGranted currentInstance [ tokenKey ] token
    Expect.isOk isGrantedByGroup tc.Description

    let isNotGrantedByGroup = Group tc.GroupItHasNot |> SymmetricJWT.isGranted currentInstance [ tokenKey ] token
    Expect.equal isNotGrantedByGroup (Error (ActionIsNotGranted "You are not authorized for this action.")) tc.Description

    isGranted |> okOrFail

[<Tests>]
let jwtTest =
    testList "Authorization - JWT" [
        yield!
            provideJWTClientId
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let client =
                        match tc.Headers with
                        | JWT.HasJWTAuthorization (JWT.HasClientId (JWT.JWTClientId clientId)) -> Some clientId
                        | _ -> None

                    Expect.equal tc.Expected client tc.Description
            )

        yield!
            provideJWTSymmetricToken
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let currentInstance = instance "prc-jwt-test-test"
                    let tokenKey = JWTKey.local "edbe2f5a-4d4a-4975-98b6-b794532e9732"

                    let token = SymmetricJWT.create currentInstance tokenKey tc.CustomData

                    let isGranted = token |> validateJWT currentInstance tokenKey tc

                    let renewedToken = isGranted |> SymmetricJWT.renew tokenKey
                    renewedToken
                    |> validateJWT currentInstance tokenKey {
                        tc with
                            Description = tc.Description + " - renewed"
                            ExpectedClientId = None // client_id is not passed to renew token ATM
                    }
                    |> ignore
            )
    ]
