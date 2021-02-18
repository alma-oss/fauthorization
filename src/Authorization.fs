namespace Lmc.Authorization

[<RequireQualifiedAccess>]
module Authorize =
    open Lmc.SC.DomainModel
    open Lmc.Authorization.Common
    open Lmc.ErrorHandling

    open Lmc.ErrorHandling.Result.Operators

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

    let private isGranted currentApplication keyForRenewToken keysForToken permission (SecurityToken token) =
        permission
        |> JWTToken.isGranted currentApplication keysForToken token
        <!> (JWTToken.renew keyForRenewToken >> RenewedToken)

    type Authorize<'RequestData> = CurrentApplication -> AuthorizedFor -> KeyForRenewToken -> JWTKey list -> SecureRequest<'RequestData> -> Result<RenewedToken * 'RequestData, AuthorizationError>

    let withLogin: Authorize<'RequestData> =
        fun currentApplication _ keyForRenewToken keysForToken ->
            SecureRequest.accessData (isGranted currentApplication keyForRenewToken keysForToken ValidToken)

    let private grantScope currentApplication authorizedFor keyForRenewToken keysForToken token scope =
        let permission =
            scope
            |> PermissionGroup.create authorizedFor
            |> Group

        token
        |> isGranted currentApplication keyForRenewToken keysForToken permission

    let withScope scope: Authorize<'RequestData> =
        fun currentApplication softwareComponent keyForRenewToken keysForToken ->
            SecureRequest.accessData (fun token ->
                scope |> grantScope currentApplication softwareComponent keyForRenewToken keysForToken token
            )

    let withScopeByRequest (scopeFromRequest: 'RequestData -> Scope): Authorize<'RequestData> =
        fun currentApplication softwareComponent keyForRenewToken keysForToken ->
            SecureRequest.access (fun token ->
                scopeFromRequest >> grantScope currentApplication softwareComponent keyForRenewToken keysForToken token
            )

    let withScopeResultFromRequest (scopeResultFromRequest: 'RequestData -> Result<Scope, ErrorMessage>): Authorize<'RequestData> =
        fun currentApplication softwareComponent keyForRenewToken keysForToken ->
            SecureRequest.access (fun token ->
                scopeResultFromRequest >@> RequestError
                >=> (grantScope currentApplication softwareComponent keyForRenewToken keysForToken token)
            )

    open Lmc.ErrorHandling.AsyncResult.Operators

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

    /// Helper function to create an Operator for easier authorization
    let authorizeAction
        (currentApplication: CurrentApplication)
        (softwareComponent: AuthorizedFor)
        (keyForRenewToken: KeyForRenewToken)
        (keysForToken: JWTKey list)
        (formatError: string -> 'ErrorMessage)
        (logAuthorizationError: string -> unit)
        (authorize: Authorize<'RequestData>)
        (action: 'RequestData -> AsyncResult<'ResponseData, 'ErrorMessage>)
        (request: SecureRequest<'RequestData>): AsyncResult<RenewedToken * 'ResponseData, SecuredRequestError<'ErrorMessage>>
        = asyncResult {
            let! (renewedToken, requestData) =
                request
                |> authorize currentApplication softwareComponent keyForRenewToken keysForToken
                |> AsyncResult.ofResult <@> (AuthorizationError.format formatError logAuthorizationError)

            let! response =
                requestData
                |> action <@> SecuredRequestError.OtherError

            return renewedToken, response
        }
