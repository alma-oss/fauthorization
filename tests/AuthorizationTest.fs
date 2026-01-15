module Alma.Authorization.AuthorizationTest

open Expecto

open System.IO
open System.Net
open Alma.ServiceIdentification
open Feather.ErrorHandling
open Alma.Authorization

let okOrFail = function
    | Ok x -> x
    | Error e -> failtestf "%A" e

let instance (instance: string) = Create.Instance(instance) |> okOrFail

let (/) a b = Path.Combine(a, b)
let model file = ModelFilePath (__SOURCE_DIRECTORY__ / "Fixtures" / file)
let policy file = PolicyFilePath (__SOURCE_DIRECTORY__ / "Fixtures" / file)
let scope scope = Scope.parse scope |> okOrFail

type AuthorizationTestCase = {
    Description: string
    Subject: Subject
    Scope: Scope
    Model: Model
    Policy: Policy
    Expected: Result<unit, AuthorizationError>
}

let provideAuthorizations: AuthorizationTestCase list = [
    // Data Auditor (read-only)
    {
        Description = "RBAC - data-auditor should authorize read"
        Subject = Subject "user"
        Scope = scope "data:read"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
    {
        Description = "RBAC - data-auditor should not authorize write"
        Subject = Subject "user"
        Scope = scope "data:write"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Error AuthorizationError.AuthorizationDenied
    }
    {
        Description = "RBAC - data-auditor should not authorize admin"
        Subject = Subject "user"
        Scope = scope "data:admin"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Error AuthorizationError.AuthorizationDenied
    }

    // Customer Care (read/write)
    {
        Description = "RBAC - customer-care should authorize read"
        Subject = Subject "user@custom-care.test"
        Scope = scope "data:read"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
    {
        Description = "RBAC - customer-care should authorize write"
        Subject = Subject "user@custom-care.test"
        Scope = scope "data:write"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
    {
        Description = "RBAC - customer-care should not authorize admin"
        Subject = Subject "user@custom-care.test"
        Scope = scope "data:admin"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Error AuthorizationError.AuthorizationDenied
    }

    // Admin (full access)
    {
        Description = "RBAC - admin should authorize read"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:read"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
    {
        Description = "RBAC - admin should authorize write"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:write"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
    {
        Description = "RBAC - admin should authorize admin"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:admin"
        Model = RBAC
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }

    // Admin (NOT a full access)
    {
        Description = "RBAC-model - admin should NOT authorize read"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:read"
        Model = model "rbac_model.conf"
        Policy = policy "adminConsole.csv"
        Expected = Error AuthorizationError.AuthorizationDenied
    }
    {
        Description = "RBAC-model - admin should NOT authorize write"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:write"
        Model = model "rbac_model.conf"
        Policy = policy "adminConsole.csv"
        Expected = Error AuthorizationError.AuthorizationDenied
    }
    {
        Description = "RBAC-model - admin should authorize admin"
        Subject = Subject "admin@domain.test"
        Scope = scope "data:admin"
        Model = model "rbac_model.conf"
        Policy = policy "adminConsole.csv"
        Expected = Ok ()
    }
]

[<Tests>]
let jwtTest =
    testList "Authorization" [
        yield!
            provideAuthorizations
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let enforcer = Authorization.createEnforcer tc.Model tc.Policy |> okOrFail
                    let granted = Authorization.enforce enforcer tc.Scope tc.Subject

                    Expect.equal granted tc.Expected tc.Description
            )
    ]
