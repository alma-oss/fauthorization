namespace Alma.Authorization

module Session =
    open Alma.ServiceIdentification
    open Alma.Authorization.Common
    open Alma.Authorization.JWT

    type Authorization = {
        CurrentApplication: Instance

        /// Key used to renew the token (write)
        KeyForRenewToken: JWTKey

        /// Key used to authorize the action (read)
        AuthorizedBy: JWTKey
    }

    [<RequireQualifiedAccess>]
    module Authorize =
        open Feather.ErrorHandling

        type GrantedAccess = private {
            RenewedToken: RenewedToken
            SessionData: SessionData
        }

        type private AuthorizeToken = SecurityToken -> AsyncResult<GrantedAccess, AuthorizationError>

        [<RequireQualifiedAccess>]
        module private SecureRequest =
            let accessData (authorizeToken: AuthorizeToken) { Token = token; RequestData = data } = asyncResult {
                let! grantedAccess = authorizeToken token

                return grantedAccess, data
            }

        let private authorize authorization permission: AuthorizeToken = fun (SecurityToken token) -> asyncResult {
            let! grantedSessionData =
                token
                |> SessionJWT.authorize authorization.CurrentApplication authorization.AuthorizedBy permission

            let! renewedToken =
                grantedSessionData
                |> SessionJWT.renew authorization.KeyForRenewToken
                |> AsyncResult.mapError InvalidKey

            return {
                RenewedToken = renewedToken
                SessionData = SessionJWT.sessionData grantedSessionData
            }
        }

        type Authorize<'RequestData> = Authorization -> SecureRequest<'RequestData> -> AsyncResult<GrantedAccess * 'RequestData, AuthorizationError>

        let withLogin: Authorize<'RequestData> =
            fun authorization ->
                SecureRequest.accessData (authorize authorization ValidToken)

        let withGroup group: Authorize<'RequestData> =
            fun authorization ->
                SecureRequest.accessData (authorize authorization (Group group))

        (*
        let private grantScope instance appKey keysForToken token scope =
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
                | InvalidKey key ->
                    logError <| sprintf "Invalid key for JWT operation: %s" key
                    "Unexpected authorization error." |> formatError |> SecuredRequestError.TokenError

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
                let! grantedAccess, requestData =
                    request
                    |> authorize authorization
                    <@> AuthorizationError.format formatError logAuthorizationError

                let action =
                    match action with
                    | Request request -> request
                    | RequestWithUsername request ->
                        grantedAccess.SessionData.Username
                        |> request

                let! response =
                    requestData
                    |> action <@> SecuredRequestError.OtherError

                return grantedAccess.RenewedToken, response
            }
