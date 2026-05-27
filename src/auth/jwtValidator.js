"use strict";

const crypto = require("node:crypto");
const { decodeBase64Url } = require("./base64url");
const { getSigningKey } = require("./jwksCache");
const {
  MalformedTokenError,
  UnsupportedAlgorithmError,
  UnknownKeyError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError
} = require("./errors");

const ALLOWED_ALGORITHMS = new Set(["RS256"]);
const DEFAULT_CLOCK_SKEW_SECONDS = 30;

function parseJsonObject(segment) {
  try {
    const parsed = JSON.parse(decodeBase64Url(segment).toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("JWT segment is not a JSON object");
    }
    return parsed;
  } catch (err) {
    throw new MalformedTokenError("Token segment was not valid JSON");
  }
}

function parseToken(token) {
  if (typeof token !== "string") {
    throw new MalformedTokenError("Token must be a string");
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new MalformedTokenError("Token must have three segments");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = parseJsonObject(encodedHeader);
  const payload = parseJsonObject(encodedPayload);
  let signature;

  try {
    signature = decodeBase64Url(encodedSignature);
  } catch (err) {
    throw new MalformedTokenError("Signature was not valid base64url");
  }

  return { encodedHeader, encodedPayload, signature, header, payload };
}

function verifySignature(encodedHeader, encodedPayload, signature, jwk) {
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  } catch (err) {
    throw new InvalidSignatureError("JWKS key could not be used for verification");
  }

  const signingInput = Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii");
  const valid = crypto.verify("RSA-SHA256", signingInput, publicKey, signature);
  if (!valid) {
    throw new InvalidSignatureError("Signature verification failed");
  }
}

function validateTimes(payload, clockSkewSeconds) {
  const now = Math.floor(Date.now() / 1000);

  if (typeof payload.exp !== "number" || payload.exp <= now - clockSkewSeconds) {
    throw new TokenExpiredError("Token is expired");
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number" || payload.nbf > now + clockSkewSeconds) {
      throw new TokenNotYetValidError("Token is not yet valid");
    }
  }
}

function validateIssuer(payload, issuer) {
  if (payload.iss !== issuer) {
    throw new IssuerMismatchError("Issuer did not match");
  }
}

function validateAudience(payload, audience) {
  if (typeof payload.aud === "string" && payload.aud === audience) {
    return;
  }

  if (Array.isArray(payload.aud) && payload.aud.includes(audience)) {
    return;
  }

  throw new AudienceMismatchError("Audience did not match");
}

async function validateToken(token, options) {
  const opts = options || {};
  const clockSkewSeconds = opts.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
  const { encodedHeader, encodedPayload, signature, header, payload } = parseToken(token);

  // A verifier must use a positive allowlist. Rejecting only "none" lets an
  // attacker choose surprising algorithms, including RS256-to-HS256 confusion.
  if (!ALLOWED_ALGORITHMS.has(header.alg)) {
    throw new UnsupportedAlgorithmError("JWT algorithm is not supported");
  }

  const jwk = await getSigningKey(header.kid, opts);
  if (!jwk) {
    throw new UnknownKeyError("JWT key id was not found");
  }

  verifySignature(encodedHeader, encodedPayload, signature, jwk);
  validateTimes(payload, clockSkewSeconds);
  validateIssuer(payload, opts.issuer);
  validateAudience(payload, opts.audience);

  return payload;
}

module.exports = { validateToken };
