"use strict";

const crypto = require("node:crypto");
const nock = require("nock");
const { validateToken } = require("../src/auth/jwtValidator");
const { _clearJwksCacheForTests } = require("../src/auth/jwksCache");
const {
  MalformedTokenError,
  UnsupportedAlgorithmError,
  UnknownKeyError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
  JwksFetchError
} = require("../src/auth/errors");

const ISSUER = "https://auth.example.com/";
const AUDIENCE = "https://api.example.com";
const JWKS_ORIGIN = "https://auth.example.com";
const JWKS_PATH = "/.well-known/jwks.json";
const JWKS_URI = `${JWKS_ORIGIN}${JWKS_PATH}`;

function encodeBase64Url(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createRsaKeyPair(kid = "kid_1") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  publicJwk.kid = kid;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  return { publicJwk, privateKey };
}

function createToken({ privateKey, kid = "kid_1", alg = "RS256", payload = {}, sign = true }) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg, kid };
  const claims = {
    sub: "user_abc123",
    iss: ISSUER,
    aud: AUDIENCE,
    exp: now + 300,
    ...payload
  };
  const encodedHeader = encodeBase64Url(JSON.stringify(header));
  const encodedPayload = encodeBase64Url(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  let signature = Buffer.from("signature");
  if (sign && alg === "RS256") {
    signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey);
  } else if (sign && alg === "HS256") {
    signature = crypto.createHmac("sha256", "secret").update(signingInput).digest();
  }

  return `${signingInput}.${encodeBase64Url(signature)}`;
}

function mockJwks(keys, status = 200) {
  global.fetch.mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    json: async () => ({ keys })
  });
}

const options = {
  jwksUri: JWKS_URI,
  issuer: ISSUER,
  audience: AUDIENCE
};

beforeAll(() => {
  nock.disableNetConnect();
});

beforeEach(() => {
  global.fetch = jest.fn();
});

afterAll(() => {
  nock.enableNetConnect();
});

afterEach(() => {
  nock.cleanAll();
  _clearJwksCacheForTests();
  jest.restoreAllMocks();
});

test("valid RS256 token passes", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const token = createToken(keys);

  await expect(validateToken(token, options)).resolves.toMatchObject({ sub: "user_abc123" });
});

test("malformed token with wrong number of parts throws MalformedTokenError", async () => {
  await expect(validateToken("a.b", options)).rejects.toBeInstanceOf(MalformedTokenError);
  await expect(validateToken("a.b.c.d", options)).rejects.toBeInstanceOf(MalformedTokenError);
});

test("invalid base64url or JSON throws MalformedTokenError", async () => {
  await expect(validateToken("not+base64.e30.signature", options)).rejects.toBeInstanceOf(
    MalformedTokenError
  );

  const badJson = `${encodeBase64Url("{")}.${encodeBase64Url("{}")}.${encodeBase64Url("x")}`;
  await expect(validateToken(badJson, options)).rejects.toBeInstanceOf(MalformedTokenError);
});

test("empty header or payload object throws MalformedTokenError", async () => {
  const emptyHeader = `${encodeBase64Url("{}")}.${encodeBase64Url(
    JSON.stringify({ sub: "user_abc123" })
  )}.abc`;
  const emptyPayload = `${encodeBase64Url(
    JSON.stringify({ alg: "RS256", kid: "kid_1" })
  )}.${encodeBase64Url("{}")}.abc`;

  await expect(validateToken(emptyHeader, options)).rejects.toBeInstanceOf(MalformedTokenError);
  await expect(validateToken(emptyPayload, options)).rejects.toBeInstanceOf(MalformedTokenError);
});

test("invalid base64url signature length throws MalformedTokenError", async () => {
  const token = `${encodeBase64Url(
    JSON.stringify({ alg: "RS256", kid: "kid_1" })
  )}.${encodeBase64Url(JSON.stringify({ sub: "user_abc123" }))}.a`;

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(MalformedTokenError);
});

test("alg none throws UnsupportedAlgorithmError", async () => {
  const keys = createRsaKeyPair();
  const token = createToken({ ...keys, alg: "none", sign: false });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(UnsupportedAlgorithmError);
});

test("HS256 token is rejected even if structurally valid", async () => {
  const keys = createRsaKeyPair();
  const token = createToken({ ...keys, alg: "HS256" });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(UnsupportedAlgorithmError);
});

test("unsupported algorithm throws UnsupportedAlgorithmError", async () => {
  const keys = createRsaKeyPair();
  const token = createToken({ ...keys, alg: "ES256", sign: false });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(UnsupportedAlgorithmError);
});

test("unknown kid triggers one JWKS refetch", async () => {
  const keys = createRsaKeyPair("new_kid");
  mockJwks([]);
  mockJwks([keys.publicJwk]);
  const token = createToken({ ...keys, kid: "new_kid" });

  await expect(validateToken(token, options)).resolves.toMatchObject({ sub: "user_abc123" });
  expect(global.fetch).toHaveBeenCalledTimes(2);
});

test("unknown kid still missing throws UnknownKeyError", async () => {
  const keys = createRsaKeyPair("missing_kid");
  mockJwks([]);
  mockJwks([]);
  const token = createToken({ ...keys, kid: "missing_kid" });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(UnknownKeyError);
  expect(global.fetch).toHaveBeenCalledTimes(2);
});

test("JWKS endpoint failure throws JwksFetchError", async () => {
  const keys = createRsaKeyPair();
  mockJwks([], 500);
  const token = createToken(keys);

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(JwksFetchError);
});

test("invalid signature throws InvalidSignatureError", async () => {
  const trusted = createRsaKeyPair("kid_1");
  const attacker = createRsaKeyPair("kid_1");
  mockJwks([trusted.publicJwk]);
  const token = createToken(attacker);

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(InvalidSignatureError);
});

test("expired token throws TokenExpiredError", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const now = Math.floor(Date.now() / 1000);
  const token = createToken({ ...keys, payload: { exp: now - 120 } });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(TokenExpiredError);
});

test("future nbf throws TokenNotYetValidError", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const now = Math.floor(Date.now() / 1000);
  const token = createToken({ ...keys, payload: { nbf: now + 120 } });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(TokenNotYetValidError);
});

test("issuer mismatch throws IssuerMismatchError", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const token = createToken({ ...keys, payload: { iss: "https://other.example.com/" } });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(IssuerMismatchError);
});

test("audience mismatch throws AudienceMismatchError", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const token = createToken({ ...keys, payload: { aud: "https://other-api.example.com" } });

  await expect(validateToken(token, options)).rejects.toBeInstanceOf(AudienceMismatchError);
});

test("audience array containing expected audience passes", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const token = createToken({ ...keys, payload: { aud: ["other", AUDIENCE] } });

  await expect(validateToken(token, options)).resolves.toMatchObject({ sub: "user_abc123" });
});

test("JWKS cache hit avoids second HTTP request", async () => {
  const keys = createRsaKeyPair();
  mockJwks([keys.publicJwk]);
  const first = createToken(keys);
  const second = createToken(keys);

  await validateToken(first, options);
  await validateToken(second, options);

  expect(global.fetch).toHaveBeenCalledTimes(1);
});
