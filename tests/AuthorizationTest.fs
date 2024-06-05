module Alma.Authorization.AuthorizationTest

open Expecto

open System.IO
open System.Net
open Alma.ServiceIdentification
open Alma.ErrorHandling
open Alma.Authorization
open Alma.Authorization.Common
open Alma.Authorization.JWT

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

let instance (instance: string) = Create.Instance(instance) |> okOrFail

type AuthorizationTestCase<'Data, 'Success, 'Error> = {
    Description: string
    Authorization: Authorization
    Authorize: Authorize.Authorize<'Data>
    Action: Authorize.Action<'Data, 'Success, 'Error>
    /// This is normally prepared by the client - see Alma.Fable.Authorization Secure.secureApi function
    Request: SecureRequest<'Data>
    ValidateToken: RenewedToken -> unit
    Expected: Result<'Success, SecuredRequestError<'Error>>
}

let provideAuthorizations: AuthorizationTestCase<string, string, string> list = [
    let currentApp = instance "prc-app-common-stable"
    let key = JWTKey.local "482caea0-4162-4fcd-9a29-94fd77477f7d"
    let authorization = {
        CurrentApplication = currentApp
        AuthorizedFor = currentApp
        KeyForRenewToken = key
        AuthorizedBy = AuthorizedBy.Key key
    }

    let jwt = SymmetricJWT.create currentApp key [
        CustomItem.String (UserCustomData.Username, "user")
        CustomItem.String (UserCustomData.DisplayName, "Uživatel")
        CustomItem.Strings (UserCustomData.Groups, [ "user" ])
    ]

    let action = function
        | "data" -> AsyncResult.ofSuccess "response"
        | _ -> AsyncResult.ofSuccess "wrong-response"

    {
        Description = "should authorize action with login"
        Authorization = authorization
        Authorize = Authorize.withLogin
        Action = Authorize.Action.Request action
        Request = {
            Token = SecurityToken jwt
            RequestData = "data"
        }
        ValidateToken = ignore  // todo - maybe later
        Expected = Ok "response"
    }
    {
        Description = "should authorize action with group"
        Authorization = authorization
        Authorize = Authorize.withGroup (PermissionGroup "user")
        Action = Authorize.Action.Request action
        Request = {
            Token = SecurityToken jwt
            RequestData = "data"
        }
        ValidateToken = ignore  // todo - maybe later
        Expected = Ok "response"
    }
    {
        Description = "should NOT authorize action with group"
        Authorization = authorization
        Authorize = Authorize.withGroup (PermissionGroup "admin")
        Action = Authorize.Action.Request action
        Request = {
            Token = SecurityToken jwt
            RequestData = "data"
        }
        ValidateToken = ignore  // todo - maybe later
        Expected = Error (SecuredRequestError.AuthorizationError "Action is not granted! You are not authorized for this action.")
    }
    {
        Description = "should authorize action with login and pass a username"
        Authorization = authorization
        Authorize = Authorize.withLogin
        Action =
            Authorize.Action.RequestWithUsername (fun username ->
                Expect.equal (Username "user") username "Username should be passed in."
                action
            )
        Request = {
            Token = SecurityToken jwt
            RequestData = "data"
        }
        ValidateToken = ignore  // todo - maybe later
        Expected = Ok "response"
    }
    {
        Description = "should NOT authorize action with group and not pass a username"
        Authorization = authorization
        Authorize = Authorize.withGroup (PermissionGroup "admin")
        Action =
            Authorize.Action.RequestWithUsername (fun username ->
                failtestf "Username should not be passed in."
            )
        Request = {
            Token = SecurityToken jwt
            RequestData = "data"
        }
        ValidateToken = ignore  // todo - maybe later
        Expected = Error (SecuredRequestError.AuthorizationError "Action is not granted! You are not authorized for this action.")
    }
]

[<Tests>]
let jwtTest =
    testList "Authorization - authorized action by JWT" [
        yield!
            provideAuthorizations
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    // Server side
                    let inline (>?>) authorize action =
                        Authorize.authorizeAction
                            tc.Authorization
                            id
                            (failtestf "Error: %A")
                            authorize
                            action

                    let apiAction: SecuredApiCall<_, _, _> = tc.Authorize >?> tc.Action

                    // Client side
                    let response =
                        tc.Request
                        |> apiAction
                        |> Async.RunSynchronously

                    let responseData =
                        match response with
                        | Ok (renewedToken, responseData) ->
                            tc.ValidateToken renewedToken
                            Ok responseData
                        | Error e -> Error e

                    Expect.equal responseData tc.Expected tc.Description
            )
    ]
