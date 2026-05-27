"use strict";

const express = require("express");
const { requireAuth, requireScopes } = require("../auth/middleware");

const initialDocuments = [
  { id: "doc_1", ownerSub: "user_abc123", title: "Document 1" },
  { id: "doc_2", ownerSub: "user_xyz789", title: "Document 2" }
];

function hasRole(auth, role) {
  const roles = auth?.["https://example.com/roles"];
  return Array.isArray(roles) && roles.includes(role);
}

function createDocumentsRouter(authOptions) {
  const router = express.Router();
  const documents = initialDocuments.map((document) => ({ ...document }));

  router.get("/documents", requireAuth(authOptions), (req, res) => {
    const ownedDocuments = documents.filter((document) => document.ownerSub === req.auth.sub);
    return res.json({ documents: ownedDocuments });
  });

  router.get("/documents/:id", requireAuth(authOptions), (req, res) => {
    const document = documents.find((item) => item.id === req.params.id);
    if (!document) {
      return res.status(404).json({ error: "not_found" });
    }

    if (document.ownerSub !== req.auth.sub && !hasRole(req.auth, "auditor")) {
      return res.status(403).json({ error: "forbidden" });
    }

    return res.json({ document });
  });

  router.post(
    "/documents",
    requireAuth(authOptions),
    requireScopes("documents:write"),
    (req, res) => {
      const document = {
        id: `doc_${documents.length + 1}`,
        ownerSub: req.auth.sub,
        title: req.body?.title || "Untitled Document"
      };
      documents.push(document);
      return res.status(201).json({ document });
    }
  );

  router.delete("/documents/:id", requireAuth(authOptions), (req, res) => {
    const index = documents.findIndex((item) => item.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: "not_found" });
    }

    if (documents[index].ownerSub !== req.auth.sub) {
      return res.status(403).json({ error: "forbidden" });
    }

    documents.splice(index, 1);
    return res.status(204).send();
  });

  return router;
}

module.exports = { createDocumentsRouter };
