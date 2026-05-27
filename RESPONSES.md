# Written Responses

## Question 1

Yes, I would treat this as a real vulnerability if `redirect_uri` was sent in the original authorization request but is not checked again during the token exchange.

The authorization code should be bound to the same redirect URI that was used when the code was issued. If the token endpoint does not check that, an attacker who can obtain or inject an authorization code may be able to redeem it in a different redirect/client context than the one originally intended.

PKCE helps because the attacker still needs the `code_verifier`, but PKCE does not replace `redirect_uri` validation. They protect different parts of the flow. PKCE proves possession of the verifier. `redirect_uri` validation makes sure the code is being redeemed in the same redirect context. The fix is to enforce an exact `redirect_uri` match at the token endpoint.

## Question 2

The attack here is basically a `kid` spray attack. The attacker does not need to break RS256. They can send many fake JWTs with random `kid` values and force the validator to keep trying to refresh JWKS if the implementation blindly refetches on every unknown key.

The impact is mostly availability. It can increase authentication latency, create a lot of outbound calls to the JWKS endpoint, put pressure on the identity provider, and in the worst case contribute to a DoS on the API’s auth layer.

I would handle this with a TTL-based JWKS cache, and allow only one controlled refetch when an unknown `kid` is seen because key rotation is a real case. After that, missing kids should be negative-cached briefly or protected with a minimum refresh interval. I would also rate-limit repeated invalid-token attempts and always fail closed.

## Question 3

I would not allow Service A to accept a token minted for Service B. The `aud` claim is the boundary that tells a resource server, “this token was meant for you.” If Service A ignores that and accepts Service B’s token, then a token issued for one service becomes reusable against another service.

That breaks the OAuth2 bearer-token model. A bearer token is already powerful because whoever has it can use it. So the audience check is one of the controls that limits where that token is valid.

The correct pattern is to issue or exchange a token for the actual service being called. If Service A needs to call Service B on behalf of the user, use token exchange/downscoping or another internal token with Service B as the audience. For pure backend-to-backend calls, client credentials can be used. Another option is an API gateway that validates the external token and mints internal audience-specific tokens. But Service A should not simply treat Service B’s token as valid for itself.

## Question 4

A 5-minute access token is better from a security point of view. If the token is stolen, the damage window is smaller. It also means account deactivation or permission changes take effect sooner in practice, because the old token expires quickly.

The downside is operational and user experience related. The client has to refresh more often, refresh-token rotation happens more frequently, the auth server gets more traffic, and mobile clients with poor connectivity may have a worse experience.

A 60-minute token is easier for the client and reduces refresh traffic. But if that token is compromised, it remains useful for a much longer time. Also, if a user is deactivated, the API may still accept the token until it expires unless we do extra server-side checks.

My default choice for sensitive APIs would be around 5 to 15 minutes, combined with refresh-token rotation and reuse detection. I would only move closer to 60 minutes for lower-risk APIs, mobile/offline-heavy use cases, or if there are strong server-side active-session checks in place.

## Question 5

This can happen because a JWT access token is stateless. If the signature is valid, the token is not expired, and issuer/audience checks pass, the API has no automatic way to know that the user was deactivated after the token was issued.

There are a few ways to handle it. We can use shorter access-token lifetimes, revoke refresh tokens and sessions, maintain a denylist using `jti`, use token introspection, do backend active-user checks, or use event-driven cache invalidation when a user is deactivated.

For a system with around 50,000 active users, I would not introspect every request unless the system is extremely sensitive, because that adds latency and couples every API call to the authorization server. My recommendation would be short-lived access tokens, immediate refresh-token/session revocation, and a cached active-user check for sensitive operations. When a user is deactivated, publish an event to invalidate or update the user-status cache quickly.

## Question 6

The first reviewer is right under the correct threat model: the refresh tokens are high-entropy random opaque values.

For that kind of token, a fast hash like SHA-256 is generally acceptable, and I would prefer HMAC-SHA-256 with a server-side pepper if possible. The reason is that an attacker who steals the database still cannot realistically guess the original token if the token has enough entropy.

Bcrypt and Argon2 are designed for human passwords, which are low entropy and guessable. If the refresh token is low entropy, the real fix is to generate stronger refresh tokens, not to compensate with password hashing. I would also use constant-time comparison, refresh-token rotation, expiry, and reuse detection.

## Question 7

I would avoid representing tenant access as OAuth scopes like `tenant:acme:read`. It may look simple at first, but it does not scale well. As tenants and permissions grow, the token can become huge, scopes become hard to manage, and revocation is awkward because the old token keeps carrying stale tenant access until it expires.

A custom JWT claim is better if we only need to represent something compact, like the active tenant ID. But I would still be careful about putting too much tenant membership data in the token. It can become stale, and if a user belongs to many organizations, the token can grow quickly.

The cleanest approach for this case management system is application-layer tenancy. The token should identify the user using `sub`. The application should then resolve the user’s current tenant membership and tenant-scoped role from the system of record, usually through a DB or cache lookup. That gives better revocability and auditability, and it keeps the token small.

My recommendation would be: keep `sub` in the token, enforce tenant membership and roles in the application layer, and optionally include a single active tenant ID claim only after the backend validates that the user belongs to that tenant. I would revisit this only if tenant membership is small, mostly static, and latency requirements justify carefully cached claims.