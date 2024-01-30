module Alma.Authorization.JWTTest

open Expecto

open System.IO
open System.Net
open Alma.Authorization

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

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
    ]
