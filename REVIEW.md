# Code Review Findings

## 1. JWKS Is Cached Forever

- Vulnerability name: JWKS cache without TTL
- Category: key rotation failure
- Severity: High
- Exploit scenario: The JWKS is loaded once and then reused forever. If the identity provider rotates signing keys, this API may reject valid new tokens. Worse, if an old signing key was compromised and rotated out, this service could still keep trusting it because the cached key never expires.
- Exact fix: Add a JWKS cache TTL. Refresh the JWKS when the TTL expires, and also do one controlled refresh when an unknown `kid` is seen. If the JWKS endpoint cannot be fetched, fail closed instead of accepting the token.

## 2. Authorization Header Parsing Is Too Loose

- Vulnerability name: Weak Authorization header parsing
- Category: authentication parsing weakness
- Severity: Medium
- Exploit scenario: The code does `auth.split(" ")[1]`, so it does not really verify that the header is in the expected `Bearer <token>` format. Malformed headers or unexpected spacing can lead to ambiguous token extraction.
- Exact fix: Require the exact bearer-token format. For example, reject the request unless the header has the scheme `Bearer` and a non-empty token value. Anything else should return a safe invalid-token response.

## 3. Token Is Decoded Before It Is Verified

- Vulnerability name: Using unverified token content for security decisions
- Category: unsafe token parsing
- Severity: High
- Exploit scenario: `jwt.decode()` does not validate the token. It only parses attacker-controlled content. In this code, the decoded header is then used to decide the `kid` and algorithm. That means the attacker is influencing the validation path before the token has been trusted.
- Exact fix: Treat decoded header fields as untrusted input. Parse only the minimum header information needed for `kid` lookup and algorithm allowlist checks. Do not trust any payload claims until the signature is successfully verified.

## 4. Attacker-Controlled `kid` Is Reflected Back

- Vulnerability name: Reflected key identifier
- Category: information disclosure / response reflection
- Severity: Low/Medium
- Exploit scenario: If an attacker sends a token with a random `kid`, the API returns that `kid` in the response. This is not the biggest issue in the file, but it is unnecessary reflection of attacker-controlled input and can create noisy logs or responses.
- Exact fix: Return a stable typed error like `{ error: "invalid_token", reason: "UnknownKeyError" }`. If the `kid` is logged internally, sanitize it and keep it out of public responses.

## 5. Cached JWKS Is Leaked in the Error Response

- Vulnerability name: JWKS cache disclosure
- Category: information disclosure
- Severity: Medium
- Exploit scenario: When the key is not found, the response includes `cachedKeys`. That exposes internal key metadata and implementation details to anyone who sends a token with an unknown `kid`.
- Exact fix: Never return the JWKS cache in an API response. Keep any key-resolution details in restricted internal logs or metrics only.

## 6. Algorithm Is Taken From the Token Header

- Vulnerability name: Attacker-selected verification algorithm
- Category: token forgery
- Severity: Critical
- Exploit scenario: The code uses `algorithms: [decoded?.header?.alg]`. This means the token decides which algorithm the server should accept. That is dangerous because it opens the door to algorithm confusion attacks, including RS256-to-HS256 style issues.
- Exact fix: The server should decide allowed algorithms, not the token. Use a hardcoded positive allowlist like `["RS256"]` and reject everything else before signature verification.

## 7. Audience Is Not Validated

- Vulnerability name: Missing audience validation
- Category: token replay / authorization bypass
- Severity: Critical
- Exploit scenario: The code checks issuer but does not check `aud`. A token issued for a different API could be replayed against this API if it has a valid signature and issuer.
- Exact fix: Validate the `aud` claim against this API’s expected audience. Support both string and array audience formats, but require the expected API audience to be present.

## 8. Raw Error Messages Are Returned

- Vulnerability name: Raw authentication error disclosure
- Category: information disclosure
- Severity: Medium
- Exploit scenario: The catch block returns `err.message` directly. That can leak parser errors, crypto errors, library behavior, or configuration details. Attackers can use this information to probe how the validator works.
- Exact fix: Map internal errors to safe typed responses. For example, return `{ error: "invalid_token", reason: "InvalidSignatureError" }` instead of raw messages or stack traces.

## 9. `key.n` Is Used as the Verification Key

- Vulnerability name: Incorrect RSA public key handling
- Category: broken crypto / key handling
- Severity: High
- Exploit scenario: `key.n` is only the RSA modulus from the JWK. It is not a complete public key. Verification may fail or push future maintainers toward unsafe conversion workarounds.
- Exact fix: Convert the full JWK into a real public key using `crypto.createPublicKey({ key: jwk, format: "jwk" })` or a correct JWK-to-PEM conversion. Use that public key for verification.

## 10. Unknown `kid` Handling Is Not Rotation-Aware

- Vulnerability name: Missing controlled JWKS refresh on unknown key
- Category: key rotation / availability
- Severity: Medium
- Exploit scenario: Since the JWKS is cached forever, the service will not pick up newly rotated keys. If someone later changes the code to refetch on every unknown `kid`, that could create another issue where attackers send many random `kid` values and force repeated JWKS calls.
- Exact fix: On unknown `kid`, do one controlled JWKS refresh to handle key rotation. Add throttling or short negative caching so random unknown kids cannot cause repeated outbound fetches. If the key is still missing after refresh, reject the token.

## 11. 403 Response Shape Is Inconsistent

- Vulnerability name: Inconsistent authorization error response
- Category: authorization response consistency
- Severity: Low
- Exploit scenario: `sendStatus(403)` returns a different response shape compared to the JSON error responses used elsewhere. This makes client behavior less predictable and can reveal differences in authorization paths.
- Exact fix: Return a consistent JSON body, for example `{ "error": "insufficient_role" }`, just like the other authorization failures.