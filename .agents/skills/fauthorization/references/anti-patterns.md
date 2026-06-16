# Anti-Patterns

Format: **mistake → why it fails → fix.**

## Keys

- **Using a `JWTKey.External` to validate or read a token → fails → `External` keys are signing-only; `JWTKey.readKey` rejects them.** Validate with the matching `Symmetric` key or the `Asymmetric` *public* PEM; reserve `External` for the signing/renew step.
- **Reading with a private key or signing with a public key → fails → validation expects a public/symmetric key and signing expects a private/symmetric key.** Use `JWTKey.Asymmetric.publicPem` for `AuthorizedBy` and `privatePem` (or the symmetric key) for `KeyForRenewToken`.
- **Reusing one key field for both roles without thinking → why → it blocks key rotation and can leak signing material into validation paths.** Keep `AuthorizedBy` and `KeyForRenewToken` explicit even when identical today.
- **Generating a fresh symmetric key per request → fails → tokens become unverifiable on the next call.** Generate once at startup (`JWTKey.Symmetric.generate`) or load a fixed key via `JWTKey.Symmetric.tryParse`.

## Validation

- **Calling raw `JWT.authorize` with an empty `Requirement` list when you needed expiry/issuer/audience checks → why → the token is accepted regardless of age or origin.** Pass `NotExpired`, `IssuedBy`, `IntendedFor` explicitly, or use `SessionJWT.authorize`, which applies all three.
- **Re-implementing the expiry/issuer/audience checks around `SessionJWT.authorize` → why → they are already applied, so the duplicate logic drifts out of sync.** Trust `SessionJWT.authorize` and only add a `Permission` (`Group` / scope) on top.
- **Hand-parsing the `Authorization` header or base64 payload → why → brittle and misses the `Bearer ` prefix and type coercion.** Use `HasJWTAuthorization` to extract the token and `HasClientId` / `HasUsername` / `HasDisplayName` to read claims.

## RBAC / Scope

- **Passing a scope string that is not `"object:capability"` → fails → `Scope.parse` returns `ScopeParseError.InvalidFormat`.** Always format scopes as exactly one `object`, one `:`, one `capability`.
- **Removing or relocating the bundled `rbac_model.conf` → fails → `Model.RBAC` loads it from the output directory and `createEnforcer` returns `EnforcerCreationError.ModelAndPolicyRequired`.** Keep the model copied to output, or supply an explicit `Model.ModelFilePath`.
- **Pointing `createEnforcer` at non-existent model/policy paths → fails → it checks `File.Exists` and errors out.** Verify both files exist before building the enforcer.
- **Using `enforce` against a purpose-aware policy (or `enforceWithPurpose` against a plain model) → why → the Casbin request arity won't match the model and every check is denied.** Match the function to the model: `enforce` for object/action models, `enforceWithPurpose` for purpose models.

## Sessions & Endpoints

- **Discarding the `RenewedToken` returned by a secured action → why → the caller's session silently expires.** Always return the renewed token to the client.
- **Putting authorization logic inside the action body instead of the guard → why → it bypasses the uniform `authorizeAction` error/logging translation.** Express access rules through `withLogin` / `withGroup` / `withScope`; keep the action focused on the request.

## Content

- **Embedding business/domain identifiers, role names, or PII beyond what authorization needs into token claims → why → bloats tokens and leaks domain data into a shared library boundary.** Store only neutral identity and the minimal claims required for the decision.
