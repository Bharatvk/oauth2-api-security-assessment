# OAuth2 API Security Assessment

Backend-only Node.js assessment focused on OAuth2 access-token validation, JWKS caching, and API authorization. There is no frontend, database, ORM, Docker setup, deployment script, or real Auth0 integration.

## Run

```sh
npm install
npm test
npm start
```

`npm start` requires:

```text
JWKS_URI=https://auth.example.com/.well-known/jwks.json
ISSUER=https://auth.example.com/
AUDIENCE=https://api.example.com
```

Tests call `createApp(authOptions)` directly, so importing the app does not require environment variables.

## Test Coverage

The Jest suite covers:

- the JWT validation chain and every typed error path
- JWKS cache hits, controlled unknown-`kid` refetch, and fetch failure
- middleware response contracts for missing, invalid, underscoped, and under-roled tokens
- route-level authorization, document ownership, auditor read access, and owner-only deletes

Tests generate RSA keys dynamically with `node:crypto`. No real private keys or secrets are committed. JWKS HTTP is mocked and tests do not make real external HTTP requests.

## JWT Validation Decisions

`validateToken(token, options)` validates in this order:

1. token structure, base64url, and JSON object parsing
2. explicit algorithm allowlist
3. `kid` resolution from JWKS
4. RS256 signature verification
5. `exp`
6. `nbf`
7. exact `iss`
8. string or array `aud`

The verifier allows only `RS256`. A denylist such as "reject only `none`" is unsafe because the token header is attacker-controlled. The verifier must decide acceptable algorithms; otherwise algorithm confusion bugs, including RS256-to-HS256 confusion, can turn key material meant for asymmetric verification into an HMAC secret.

Signature verification uses the exact JWT signing input, `encodedHeader + "." + encodedPayload`, and the decoded signature bytes from the third segment.

## JWKS Cache

The default JWKS cache TTL is 10 minutes. That keeps normal requests off the JWKS endpoint, reduces auth latency, and still lets key rotations propagate quickly enough for this size of API.

An unknown `kid` with a warm cache triggers one controlled refetch because key rotation may have introduced a new signing key. Arbitrary unknown `kid` values are also negative-cached and forced refreshes are throttled, so a kid-spray attack cannot cause unlimited JWKS fetches. If JWKS cannot be fetched or parsed, validation fails closed.

## Authorization Design

Scopes and roles are generic token-claim checks, so they live in middleware:

- `requireScopes(...scopes)` checks the space-delimited `scope` claim.
- `requireRole(role)` checks `https://example.com/roles`.

Ownership is resource-specific. The API has to load the document before it can compare `document.ownerSub` with `req.auth.sub`, so ownership checks stay inside route handlers near the resource logic. Keeping this check generic would invite incorrect assumptions across resources with different ownership rules.

## Error Responses

401 responses include only a stable typed reason such as `TokenExpiredError`. They do not expose stack traces, raw crypto errors, raw library messages, tokens, JWKS contents, or key material. This gives clients enough information to react while avoiding response-based information disclosure.

## No Secrets

`.env.example` contains placeholders only. Tests generate temporary key pairs at runtime. No real private keys, refresh tokens, access tokens, or Auth0 secrets are committed.
