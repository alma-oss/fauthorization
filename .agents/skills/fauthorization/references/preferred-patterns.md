# Preferred Patterns

## Core Principles

- All public modules use `[<RequireQualifiedAccess>]`; always qualify calls (`JWT.create`, `SessionJWT.authorize`, `Authorize.withLogin`).
- Domain types are single-case discriminated unions (`Issuer`, `Audience`, `Subject`, `Object`, `Capability`); construct and destructure them explicitly.
- Token creation and external signing are asynchronous (`AsyncResult`); validation of an already-loaded token is synchronous (`Result`). Compose them inside `asyncResult { }` / `result { }` from `Feather.ErrorHandling`.
- Keep token payloads neutral and minimal — put only identity/claims data needed for authorization decisions, never project-specific business state.

## Recommended API Usage

- **Two distinct keys.** A `Session.Authorization` record carries `AuthorizedBy` (used to validate/read the incoming token) and `KeyForRenewToken` (used to sign the renewed token). They are often the same key, but model them separately so rotation is possible.
- **Prefer `SessionJWT` over raw `JWT`** for app sessions. `SessionJWT.create` sets issuer = audience = the current `Instance` (joined with `-`) and defaults to a 30-minute lifetime; `SessionJWT.authorize` automatically requires `NotExpired`, `IssuedBy`, and `IntendedFor`. Use `SessionJWT.createFor` to override the expiration.
- **Use raw `JWT.create` / `JWT.authorize`** only when you need full control over issuer, audience, and the explicit `Requirement` list (e.g. validating third-party tokens).
- **Use `JWT.createWithId`** when a deterministic `jti` is required (idempotent issuance, testing); otherwise `JWT.create` generates a fresh GUID `jti`.
- **Read claims with active patterns**, not manual payload parsing: `HasJWTAuthorization` extracts a bearer token from a header `Map`, and `HasClientId` / `HasUsername` / `HasDisplayName` read individual claims. See `examples.md` → Basic Example.
- **Construct keys via the provided constructors**: `JWTKey.Symmetric.generate` / `JWTKey.Symmetric.tryParse` for HMAC, `JWTKey.Asymmetric.publicPem` / `privatePem` for RSA/ECDSA, and `JWTKey.External` for delegated signing.

## Error Handling

- Each domain exposes its own error DU plus a `format` function (`CredentialsError.format`, `Authorization.AuthorizationError.format`, `EnforcerCreationError.format`).
- Map library errors to your app's error type at the boundary with the `<@>` operator (`<@> (CredentialsError.format >> MyError)`); do not pattern-match every internal case in endpoint code.
- `Session.Authorize.authorizeAction` already translates `AuthorizationError` into `SecuredRequestError` (`TokenError`, `AuthorizationError`, `OtherError`) and routes a log callback — rely on it rather than reformatting authorization failures yourself.

## Composition

- Build a `>?>` operator once per API module by partially applying `Authorize.authorizeAction` with your `Authorization` record, error constructor, and log function; use `>?>>` (wrapping `Action.RequestWithUsername`) when the endpoint needs the authenticated `Username`. See `examples.md` → Securing an API Endpoint.
- Choose the guard by required strictness: `Authorize.withLogin` (any valid session), `Authorize.withGroup` (group membership), `Authorize.withScope` (RBAC scope via an `EnforceScope`).
- Produce an `EnforceScope` with `Session.EnforceScope.prepare enforcer subjectSelector` (or `prepareWithPurpose` for purpose-scoped models); the selector turns `TokenData` into a Casbin `Subject`.
- A successful secured call returns `RenewedToken * 'ResponseData` — always send the renewed token back to the caller so the session slides forward.

## Integration with Other Libraries

- Build an `Instance` with `Create.Instance` from `Alma.ServiceIdentification`; it feeds `SessionJWT` issuer/audience and the `Session.Authorization.CurrentApplication` field.
- Casbin RBAC: `Authorization.createEnforcer` accepts either `Model.RBAC` (which loads the bundled `rbac_model.conf` from the output directory) or `Model.ModelFilePath`, together with a `Policy.PolicyFilePath`. Parse scopes from `"object:capability"` strings with `Scope.parse`.
- `enforceWithPurpose` adds a `Purpose` dimension (from `Alma.ServiceIdentification`) and requires a purpose-aware Casbin model.
- AWS ALB: configure `AmazonJWT.ValidationDependencies` (logger, HTTP getter, expected ALB ARN, region, issuer, lifetime flag); `AmazonJWT.JWT.read` validates the signer and fetches the EC public key, while `AmazonJWT.Authenticate.withOidcHeader` reads the `x-amzn-oidc-data` header and mints a `SessionJWT`. See `examples.md` → Amazon ALB Validation.

## Naming Conventions

- Endpoint guards are named `with<Criterion>` (`withLogin`, `withGroup`, `withScope`).
- Key accessor modules mirror the key kind (`JWTKey.Symmetric`, `JWTKey.Asymmetric`).
- Error DUs are named `<Domain>Error` and always pair with a `format` function.

## Testing Recommendations

- Tests use Expecto. Build a deterministic `Symmetric` key with `JWTKey.Symmetric.tryParse` of a fixed GUID, and a deterministic `Instance` with `Create.Instance`.
- Exercise the full create → authorize → renew round trip, then re-validate the renewed token to confirm claims and group checks survive renewal.
- For `External` signing tests, supply a mock `Sign` function matching the `JWTPart.UnsignedJWT -> AsyncResult<JWTPart.Signature, string>` contract. See `examples.md` → Expecto Round-Trip Test.
