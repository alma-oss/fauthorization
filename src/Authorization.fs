namespace Alma.Authorization

open Casbin
open Feather.ErrorHandling
open Alma.ServiceIdentification
open Alma.Authorization.Common

type Subject = Subject of string

type Object = Object of string
type Capability =
    | Read
    | Write
    | Admin

type Scope = {
    Object: Object
    Capability: Capability
}

type Model =
    | ModelFilePath of string
    | RBAC

type Policy =
    | PolicyFilePath of string

[<RequireQualifiedAccess>]
type CapabilityParseError =
    | UnknownCapability of string

[<RequireQualifiedAccess>]
module Capability =
    let parse = function
        | "read" -> Ok Read
        | "write" -> Ok Write
        | "admin" -> Ok Admin
        | other -> Error (CapabilityParseError.UnknownCapability other)

    let value = function
        | Read -> "read"
        | Write -> "write"
        | Admin -> "admin"

[<RequireQualifiedAccess>]
type ScopeParseError =
    | InvalidFormat of string
    | CapabilityParseError of CapabilityParseError

[<RequireQualifiedAccess>]
module Scope =
    let parse (scope: string) = result {
        let! object, rawCapability =
            match scope.Split ":" with
            | [| object; capability |] -> Ok (Object object, capability)
            | _ -> Error (ScopeParseError.InvalidFormat scope)

        let! capability =
            rawCapability
            |> Capability.parse
            |> Result.mapError ScopeParseError.CapabilityParseError

        return {
            Object = object
            Capability = capability
        }
    }

    let forCasbin { Object = Object object; Capability = capability } =
        let action = Capability.value capability

        object, action

// Errors
[<RequireQualifiedAccess>]
type EnforcerCreationError =
    | ModelAndPolicyRequired

[<RequireQualifiedAccess>]
module EnforcerCreationError =
    let format = function
        | EnforcerCreationError.ModelAndPolicyRequired ->
            "Both model and policy file paths must be provided and exist."

[<RequireQualifiedAccess>]
type AuthorizationError =
    | EnforcerCreationError of EnforcerCreationError
    | AuthorizationDenied

[<RequireQualifiedAccess>]
module AuthorizationError =
    let format = function
        | AuthorizationError.EnforcerCreationError err ->
            EnforcerCreationError.format err

        | AuthorizationError.AuthorizationDenied ->
            "The user is not authorized for the requested action."

[<RequireQualifiedAccess>]
module Authorization =
    open System
    open System.IO

    let createEnforcer (model: Model) (policy: Policy) =
        match model, policy with
        | RBAC, PolicyFilePath policy when File.Exists policy ->
            let modelPath = Path.Combine(AppContext.BaseDirectory, "src/model/rbac_model.conf")
            Enforcer(modelPath, policy) |> Ok

        | ModelFilePath model, PolicyFilePath policy when [model; policy] |> List.forall File.Exists ->
            Enforcer(model, policy) |> Ok

        | _ ->
            Error EnforcerCreationError.ModelAndPolicyRequired

    let enforce (enforcer: Enforcer) (scope: Scope) (user: Subject): Result<unit, AuthorizationError> = result {
        let object, action = Scope.forCasbin scope
        let (Subject subject) = user

        if enforcer.Enforce(subject, object, action) then
            return ()
        else
            return! Error AuthorizationError.AuthorizationDenied
    }
