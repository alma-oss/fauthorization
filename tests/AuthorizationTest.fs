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
let authorizationTest =
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

type AuthorizationByPurposeTestCase = {
    Description: string
    Subject: Subject
    Scope: Scope
    Model: Model
    Policy: Policy
    Purpose: Purpose
    Expected: Result<unit, AuthorizationError>
}

let provideAuthorizationsByPurpose: AuthorizationByPurposeTestCase list = [
    let purposes = ["dev"; "int"; "prod"]
    let nonProdPurposes = ["dev"; "int"]

    // auditConsole - Admin (a full access)
    for purpose in purposes do
        {
            Description = $"RBAC-purpose-model - admin should authorize read on {purpose}"
            Subject = Subject "admin"
            Scope = scope "entries:read"
            Model = model "rbac_purpose_model.conf"
            Policy = policy "auditConsole.csv"
            Purpose = Purpose purpose
            Expected = Ok ()
        }

    // auditConsole - Auditor (read-only access on all purposes)
    for purpose in purposes do
        {
            Description = $"RBAC-purpose-model - auditor should authorize read on {purpose}"
            Subject = Subject "domain.auditor"
            Scope = scope "entries:read"
            Model = model "rbac_purpose_model.conf"
            Policy = policy "auditConsole.csv"
            Purpose = Purpose purpose
            Expected = Ok ()
        }

    // auditConsole - Developer (access on non-production purposes only)
    for purpose in nonProdPurposes do
        {
            Description = $"RBAC-purpose-model - developer should authorize read on {purpose}"
            Subject = Subject "developer"
            Scope = scope "entries:read"
            Model = model "rbac_purpose_model.conf"
            Policy = policy "auditConsole.csv"
            Purpose = Purpose purpose
            Expected = Ok ()
        }

    {
        Description = $"RBAC-purpose-model - developer should NOT authorize read on prod"
        Subject = Subject "developer"
        Scope = scope "entries:read"
        Model = model "rbac_purpose_model.conf"
        Policy = policy "auditConsole.csv"
        Purpose = Purpose "prod"
        Expected = Error AuthorizationError.AuthorizationDenied
    }
]

[<Tests>]
let authorizationByPurposeTest =
    testList "Authorization by purpose" [
        yield!
            provideAuthorizationsByPurpose
            |> List.map (fun tc ->
                testCase tc.Description <| fun _ ->
                    let enforcer = Authorization.createEnforcer tc.Model tc.Policy |> okOrFail
                    let granted = Authorization.enforceWithPurpose enforcer tc.Purpose tc.Scope tc.Subject

                    Expect.equal granted tc.Expected tc.Description
            )
    ]
