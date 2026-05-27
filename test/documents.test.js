"use strict";

const request = require("supertest");

jest.mock("../src/auth/jwtValidator", () => ({
  validateToken: jest.fn()
}));

const { validateToken } = require("../src/auth/jwtValidator");
const { createApp } = require("../src/app");

const authOptions = {
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  issuer: "https://auth.example.com/",
  audience: "https://api.example.com"
};

function authHeader() {
  return { Authorization: "Bearer a.b.c" };
}

function appWithAuth(payload) {
  validateToken.mockResolvedValue(payload);
  return createApp(authOptions);
}

afterEach(() => {
  jest.clearAllMocks();
});

test("GET /api/documents returns only authenticated user's documents", async () => {
  const app = appWithAuth({ sub: "user_abc123" });

  const response = await request(app).get("/api/documents").set(authHeader()).expect(200);

  expect(response.body.documents).toEqual([
    { id: "doc_1", ownerSub: "user_abc123", title: "Document 1" }
  ]);
});

test("GET /api/documents/:id allows owner", async () => {
  const app = appWithAuth({ sub: "user_abc123" });

  await request(app)
    .get("/api/documents/doc_1")
    .set(authHeader())
    .expect(200)
    .expect((res) => {
      expect(res.body.document.id).toBe("doc_1");
    });
});

test("GET /api/documents/:id allows auditor", async () => {
  const app = appWithAuth({
    sub: "user_auditor",
    "https://example.com/roles": ["auditor"]
  });

  await request(app)
    .get("/api/documents/doc_1")
    .set(authHeader())
    .expect(200)
    .expect((res) => {
      expect(res.body.document.id).toBe("doc_1");
    });
});

test("GET /api/documents/:id rejects non-owner non-auditor", async () => {
  const app = appWithAuth({ sub: "user_other" });

  await request(app)
    .get("/api/documents/doc_1")
    .set(authHeader())
    .expect(403, { error: "forbidden" });
});

test("missing document returns not_found", async () => {
  const app = appWithAuth({ sub: "user_abc123" });

  await request(app)
    .get("/api/documents/doc_missing")
    .set(authHeader())
    .expect(404, { error: "not_found" });
});

test("POST /api/documents requires documents:write", async () => {
  const app = appWithAuth({ sub: "user_abc123", scope: "documents:read" });

  await request(app)
    .post("/api/documents")
    .set(authHeader())
    .send({ title: "New Document" })
    .expect(403, { error: "insufficient_scope" });
});

test("POST /api/documents creates document for authenticated user", async () => {
  const app = appWithAuth({ sub: "user_abc123", scope: "documents:write" });

  await request(app)
    .post("/api/documents")
    .set(authHeader())
    .send({ title: "New Document" })
    .expect(201)
    .expect((res) => {
      expect(res.body.document).toMatchObject({
        ownerSub: "user_abc123",
        title: "New Document"
      });
    });
});

test("DELETE /api/documents/:id allows owner", async () => {
  const app = appWithAuth({ sub: "user_abc123" });

  await request(app).delete("/api/documents/doc_1").set(authHeader()).expect(204);
});

test("DELETE /api/documents/:id rejects auditor if auditor is not owner", async () => {
  const app = appWithAuth({
    sub: "user_auditor",
    "https://example.com/roles": ["auditor"]
  });

  await request(app)
    .delete("/api/documents/doc_1")
    .set(authHeader())
    .expect(403, { error: "forbidden" });
});
