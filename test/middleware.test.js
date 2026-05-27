"use strict";

const express = require("express");
const request = require("supertest");
const {
  MalformedTokenError,
  TokenExpiredError
} = require("../src/auth/errors");

jest.mock("../src/auth/jwtValidator", () => ({
  validateToken: jest.fn()
}));

const { validateToken } = require("../src/auth/jwtValidator");
const { requireAuth, requireScopes, requireRole } = require("../src/auth/middleware");

function createTestApp(...middleware) {
  const app = express();
  app.get("/test", ...middleware, (req, res) => res.json({ ok: true }));
  return app;
}

afterEach(() => {
  jest.clearAllMocks();
});

test("missing Authorization header returns missing_token", async () => {
  const app = createTestApp(requireAuth({}));

  await request(app).get("/test").expect(401, { error: "missing_token" });
});

test("malformed Authorization header returns MalformedTokenError", async () => {
  const app = createTestApp(requireAuth({}));

  await request(app)
    .get("/test")
    .set("Authorization", "Basic abc")
    .expect(401, { error: "invalid_token", reason: "MalformedTokenError" });
});

test("invalid token returns typed reason", async () => {
  validateToken.mockRejectedValue(new TokenExpiredError("expired"));
  const app = createTestApp(requireAuth({}));

  await request(app)
    .get("/test")
    .set("Authorization", "Bearer a.b.c")
    .expect(401, { error: "invalid_token", reason: "TokenExpiredError" });
});

test("wrong scope returns insufficient_scope", async () => {
  validateToken.mockResolvedValue({ sub: "user_abc123", scope: "documents:read" });
  const app = createTestApp(requireAuth({}), requireScopes("documents:write"));

  await request(app)
    .get("/test")
    .set("Authorization", "Bearer a.b.c")
    .expect(403, { error: "insufficient_scope" });
});

test("wrong role returns insufficient_role", async () => {
  validateToken.mockResolvedValue({
    sub: "user_abc123",
    "https://example.com/roles": ["user"]
  });
  const app = createTestApp(requireAuth({}), requireRole("auditor"));

  await request(app)
    .get("/test")
    .set("Authorization", "Bearer a.b.c")
    .expect(403, { error: "insufficient_role" });
});
