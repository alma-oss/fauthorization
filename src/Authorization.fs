namespace Alma.Authorization

open Alma.ServiceIdentification
open Alma.Authorization.Common
open Alma.Authorization.JWT

[<RequireQualifiedAccess>]
type AuthorizedBy =
    | Key of JWTKey
    | OneOf of JWTKey list

[<RequireQualifiedAccess>]
module private AuthorizedBy =
    let keys = function
        | AuthorizedBy.Key key -> [ key ]
        | AuthorizedBy.OneOf keys -> keys

type Authorization = {
    CurrentApplication: Instance
    AuthorizedFor: Instance
    KeyForRenewToken: JWTKey
    AuthorizedBy: AuthorizedBy
}

[<RequireQualifiedAccess>]
module Authorize =
    open Feather.ErrorHandling
    open Feather.ErrorHandling.Result.Operators

    [<RequireQualifiedAccess>]
    module private SecureRequest =
        let accessData assertGranted { Token = token; RequestData = data } = result {
            let! renewedToken = assertGranted token

            return renewedToken, data
        }

        let access assertGranted { Token = token; RequestData = data } = result {
            let! renewedToken = assertGranted token data

            return renewedToken, data
        }

    let private isGranted authorization permission (SecurityToken token) =
        permission
        |> SymmetricJWT.isGranted authorization.CurrentApplication (authorization.AuthorizedBy |> AuthorizedBy.keys) token
        <!> (SymmetricJWT.renew authorization.KeyForRenewToken >> RenewedToken)

    type Authorize<'RequestData> = Authorization -> SecureRequest<'RequestData> -> Result<RenewedToken * 'RequestData, AuthorizationError>

    let withLogin: Authorize<'RequestData> =
        fun authorization ->
            SecureRequest.accessData (isGranted authorization ValidToken)

    let withGroup group: Authorize<'RequestData> =
        fun authorization ->
            SecureRequest.accessData (isGranted authorization (Group group))

    (* let private grantScope instance appKey keysForToken token scope =
        let permission =
            scope
            |> Ldap.Authorization.permissionGroup instance
            |> Group

        token
        |> isGranted instance appKey keysForToken permission

    let withScope scope: Authorize<'RequestData> =
        fun instance appKey keysForToken ->
            SecureRequest.accessData (fun token ->
                scope |> grantScope instance appKey keysForToken token
            )

    let withScopeByRequest (scopeFromRequest: 'RequestData -> Scope): Authorize<'RequestData> =
        fun instance appKey keysForToken ->
            SecureRequest.access (fun token ->
                scopeFromRequest >> grantScope instance appKey keysForToken token
            )

    let withScopeResultFromRequest (scopeResultFromRequest: 'RequestData -> Result<Scope, ErrorMessage>): Authorize<'RequestData> =
        fun instance appKey keysForToken ->
            SecureRequest.access (fun token ->
                scopeResultFromRequest >@> RequestError
                >=> (grantScope instance appKey keysForToken token)
            ) *)

    open Feather.ErrorHandling.AsyncResult.Operators

    [<RequireQualifiedAccess>]
    module private AuthorizationError =
        let format (formatError: string -> 'ErrorMessage) logError: AuthorizationError -> SecuredRequestError<'ErrorMessage> = function
            | JwtValidationError (JwtValidationError.Unexpected e) ->
                logError <| sprintf "Unexpected authorization error.\n%s" e.Message
                "Unexpected authorization error." |> formatError |> SecuredRequestError.TokenError

            | JwtValidationError MissingKeyData ->
                logError "Missing key for JWT validation."
                "Unexpected authorization error." |> formatError |> SecuredRequestError.TokenError

            | JwtValidationError detail ->
                sprintf "Action is not granted! %A" detail |> formatError |> SecuredRequestError.TokenError

            | ActionIsNotGranted detail ->
                sprintf "Action is not granted! %s" detail |> formatError |> SecuredRequestError.AuthorizationError

            | RequestError error ->
                error |> formatError |> SecuredRequestError.AuthorizationError

    type Action<'RequestData, 'ResponseData, 'Error> =
        | Request of ('RequestData -> AsyncResult<'ResponseData, 'Error>)
        | RequestWithUsername of (Username -> 'RequestData -> AsyncResult<'ResponseData, 'Error>)

    /// Helper function to create an Operator for easier authorization
    let authorizeAction
        authorization
        (formatError: string -> 'Error)
        (logAuthorizationError: string -> unit)
        (authorize: Authorize<'RequestData>)
        (action: Action<'RequestData, 'ResponseData, 'Error>)
        (request: SecureRequest<'RequestData>): AsyncResult<RenewedToken * 'ResponseData, SecuredRequestError<'Error>>
        = asyncResult {
            let! (renewedToken, requestData) =
                request
                |> authorize authorization
                |> AsyncResult.ofResult <@> (AuthorizationError.format formatError logAuthorizationError)

            let! action =
                match action with
                | Request request -> Ok request
                | RequestWithUsername request ->
                    result {
                        let! username =
                            renewedToken
                            |> RenewedToken.username authorization.CurrentApplication authorization.KeyForRenewToken
                            // this error should not happen, because the token is already validated
                            |> Result.mapError (fun e -> SecuredRequestError.TokenError (formatError "Unable to get a username from the token."))

                        return request username
                    }

            let! response =
                requestData
                |> action <@> SecuredRequestError.OtherError

            return renewedToken, response
        }
