# AGENTS.md — Alma.Authorization

## Project Purpose

`Alma.Authorization` is an F# NuGet library for web application authorization. It provides JWT creation/validation, session-based authorization with token renewal, credential handling, RBAC enforcement via Casbin, external signing support (e.g., Vault Transit), and Amazon ALB JWT validation. Used by SAFE stack applications to secure API endpoints with a composable `>?>` operator pattern.

## Agent Skills

This repo ships Agent Skill for the `Alma.Authorization` library. Compatible agents discover it automatically; see `.agents/skills/fauthorization/SKILL.md`.

## Tech Stack

- **Language:** F# (.NET 10)
- **Package manager:** Paket
- **Build system:** FAKE (F# Make) via `build.sh`
- **Test framework:** Expecto
- **NuGet package:** `Alma.Authorization`
- **Repository:** <https://github.com/alma-oss/fauthorization>

## Key Dependencies

- `FSharp.Core ~> 10.0`, `FSharp.Data ~> 6.0`
- `System.IdentityModel.Tokens.Jwt ~> 8.6` — JWT handling
- `JsonWebToken ~> 1.9` — low-level JWT creation with custom signing
- `Portable.BouncyCastle ~> 1.9` — EC key parsing for Amazon ALB JWTs
- `Casbin.NET ~> 2.19` — RBAC policy enforcement
- `Alma.Authorization.Common ~> 7.0` — shared types (`User`, `Username`, `Password`, `JWT`, `SecureRequest`, etc.)
- `Alma.ServiceIdentification ~> 11.0` — `Instance`, `Issuer`, `Audience`
- `Feather.Cryptography ~> 2.0` — Base64 encoding utilities
- `Feather.ErrorHandling ~> 2.0` — `AsyncResult`, `Result` operators (`<@>`, `>=>`)

## Commands

```bash
# Install dependencies
dotnet paket install

# Build
./build.sh build

# Run tests
./build.sh -t tests
```

## Project Structure

```
├── Authorization.fsproj          # Project file (version, package metadata)
├── AssemblyInfo.fs               # Auto-generated assembly info
├── src/
│   ├── Utils.fs                  # Internal helpers (tee, String.toBytes/toBase64, List.toGeneric)
│   ├── Types.fs                  # Credentials, CredentialsError, Authenticate, ACLClient
│   ├── Token.fs                  # JWT module — creation, validation, parsing, external signing
│   ├── Authorization.fs          # RBAC authorization with Casbin (Scope, Capability, Enforcer)
│   ├── SessionAuthorization.fs   # Session module — authorize/renew flow, >?> operator
│   ├── AmazonJwt.fs              # Amazon ALB JWT validation (EC key, OIDC)
│   └── model/
│       └── rbac_model.conf       # Casbin RBAC model definition (copied to output)
│   └── schema/
│       └── aclClient.json        # JSON schema for ACL client parsing (JsonProvider)
├── tests/
│   ├── tests.fsproj              # Test project
│   ├── Tests.fs                  # Test runner entry point
│   ├── JWTTest.fs                # JWT creation/validation tests
│   ├── AuthorizationTest.fs      # RBAC authorization tests
│   ├── SessionAuthorizationTest.fs # Session flow tests
│   └── __AmazonJWTTest.fs        # Amazon JWT tests (prefixed with __ — may be disabled)
│   └── Fixtures/                 # Test fixtures
├── build/                        # FAKE build scripts
├── paket.dependencies            # Dependency definitions
├── paket.references              # References for main project
└── fsharplint.json               # Lint config
```

## Architecture

### Core Modules

1. **`Types`** — `Credentials`, `CredentialsError`, `Authenticate` (sync/async), `ACLClient` with JSON parsing
2. **`Token` (`JWT` module)** — JWT creation with `JwsDescriptor`, validation via `JwtSecurityTokenHandler`, support for:
   - `JWTKey.Symmetric` — HMAC signing
   - `JWTKey.External` — external signing (e.g., Vault Transit) with async `Sign` callback
3. **`Authorization`** — Casbin-based RBAC: `Scope` (Object + Capability), `Model`, `Policy`, `Enforcer` creation, `Authorization.enforce`
4. **`Session`** — session authorization flow:
   - `Authorize.withLogin` — validates token, renews it
   - `Authorize.withGroup` — validates token + group membership
   - `Authorize.withScope` — validates token + RBAC scope
   - `Authorize.authorizeAction` — composes authorization with API action via `>?>` operator
5. **`AmazonJWT`** — validates JWTs from AWS ALB (fetches EC public key from AWS, validates signer ARN)

### Authorization Flow

```
Client Request → SecureRequest<'Data> (token + data)
    → >?> operator → authorize (validate JWT, renew token)
    → execute action with granted access
    → return RenewedToken * 'Success
```

## Conventions

- **`>?>` operator** — composes authorization check with API action: `Authorize.withLogin >?> fun () -> asyncResult { ... }`
- **`>?>>`** — variant that passes `Username` from session to the action
- **`SecureRequest<'Data>`** — wraps `SecurityToken` + `RequestData` for every secured endpoint
- **`SecuredApiCall<'Data, 'Success, 'Error>`** — type alias for secured async API calls
- **`[<RequireQualifiedAccess>]`** on all public modules
- **Single-case DUs** for type safety (`Subject`, `Object`, `Capability`)
- **Error types** — each domain has its own error DU with a `format` function
- **`asyncResult { }` CE** — all async operations use `Feather.ErrorHandling` computation expressions

## CI/CD

| Workflow | Trigger | What it does |
|---|---|---|
| `tests.yaml` | PR, daily at 03:00 UTC | `./build.sh -t tests` on ubuntu-latest with .NET 10 |
| `publish.yaml` | Tag push (`X.Y.Z`) | `./build.sh -t publish` → NuGet.org |
| `pr-check.yaml` | PR | Blocks fixup commits, runs ShellCheck |

## Release Process

1. Increment `<Version>` in `Authorization.fsproj`
2. Update `CHANGELOG.md`
3. Commit and push a git tag matching the version (e.g., `10.0.0`)

## Pitfalls

- **No docker-compose / no local environment** — this is a pure library, no runtime services
- **`src/model/rbac_model.conf`** is copied to output (`<CopyToOutputDirectory>PreserveNewest</CopyToOutputDirectory>`); do not remove it
- **`src/schema/aclClient.json`** is used by F# Data `JsonProvider` at compile time; changing its structure breaks `ACLClient.tryParse`
- **`__AmazonJWTTest.fs`** — prefixed with `__`, may be intentionally excluded or WIP
- **External signing** — `JWTKey.External` expects an async `Sign` function; test mocks must match this contract
- **Casbin model** — the RBAC model is `rbac_model.conf`; do not modify unless you understand Casbin model syntax
- **`Feather.ErrorHandling` operators** — `<@>` maps errors, `>=>` chains results; these are not standard F# operators
