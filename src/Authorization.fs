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

    let private isGranted softwareComponent appKey keysForToken permission (SecurityToken token) =
        permission
        |> JWTToken.isGranted softwareComponent keysForToken token
        <!> (JWTToken.renew appKey >> RenewedToken)

    type Authorize<'RequestData> = Lmc.SC.DomainModel.SoftwareComponent -> JWTKey -> JWTKey list -> SecureRequest<'RequestData> -> Result<RenewedToken * 'RequestData, AuthorizationError>

    let withLogin: Authorize<'RequestData> =
        fun softwareComponent appKey keysForToken ->
            SecureRequest.accessData (isGranted softwareComponent appKey keysForToken ValidToken)

    let private grantScope softwareComponent appKey keysForToken token scope =
        let permission =
            scope
            |> PermissionGroup.create softwareComponent
            |> Group

        token
        |> isGranted softwareComponent appKey keysForToken permission

    let withScope scope: Authorize<'RequestData> =
        fun softwareComponent appKey keysForToken ->
            SecureRequest.accessData (fun token ->
                scope |> grantScope softwareComponent appKey keysForToken token
            )

    let withScopeByRequest (scopeFromRequest: 'RequestData -> Scope): Authorize<'RequestData> =
        fun softwareComponent appKey keysForToken ->
            SecureRequest.access (fun token ->
                scopeFromRequest >> grantScope softwareComponent appKey keysForToken token
            )

    let withScopeResultFromRequest (scopeResultFromRequest: 'RequestData -> Result<Scope, ErrorMessage>): Authorize<'RequestData> =
        fun softwareComponent appKey keysForToken ->
            SecureRequest.access (fun token ->
                scopeResultFromRequest >@> RequestError
                >=> (grantScope softwareComponent appKey keysForToken token)
            )

    open Lmc.ErrorHandling.AsyncResult.Operators

    [<RequireQualifiedAccess>]
    module private AuthorizationError =
        let format logError = function
            | JwtValidationError (JwtValidationError.Unexpected e) ->
                logError <| sprintf "Unexpected authorization error.\n%s" e.Message
                "Unexpected authorization error." |> SecuredRequestError.TokenError

            | JwtValidationError MissingKeyData ->
                logError "Missing key for JWT validation."
                "Unexpected authorization error." |> SecuredRequestError.TokenError

            | JwtValidationError detail ->
                sprintf "Action is not granted! %A" detail |> SecuredRequestError.TokenError

            | ActionIsNotGranted detail ->
                sprintf "Action is not granted! %s" detail |> SecuredRequestError.AuthorizationError

            | RequestError error ->
                error |> SecuredRequestError.AuthorizationError

    /// Helper function to create an Operator for easier authorization
    let authorizeAction
        (softwareComponent: Lmc.SC.DomainModel.SoftwareComponent)
        (appKey: JWTKey)
        (keysForToken: JWTKey list)
        (logAuthorizationError: string -> unit)
        (authorize: Authorize<'RequestData>)
        (action: 'RequestData -> AsyncResult<'ResponseData, ErrorMessage>)
        (request: SecureRequest<'RequestData>): AsyncResult<RenewedToken * 'ResponseData, SecuredRequestError<ErrorMessage>>
        = asyncResult {
            let! (renewedToken, requestData) =
                request
                |> authorize softwareComponent appKey keysForToken
                |> AsyncResult.ofResult <@> (AuthorizationError.format logAuthorizationError)

            let! response =
                requestData
                |> action <@> SecuredRequestError.OtherError

            return renewedToken, response
        }
