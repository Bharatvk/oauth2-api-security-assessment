"use strict";

const { validateToken } = require("./jwtValidator");
const { AuthError, MalformedTokenError } = require("./errors");

function requireAuth(options) {
  return async (req, res, next) => {
    const header = req.get("authorization");

    if (!header) {
      return res.status(401).json({ error: "missing_token" });
    }

    const match = header.match(/^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/);
    if (!match) {
      return res.status(401).json({
        error: "invalid_token",
        reason: "MalformedTokenError"
      });
    }

    try {
      req.auth = await validateToken(match[1], options);
      return next();
    } catch (err) {
      const reason = err instanceof AuthError ? err.name : "AuthError";
      return res.status(401).json({ error: "invalid_token", reason });
    }
  };
}

function requireScopes(...scopes) {
  return (req, res, next) => {
    const granted = typeof req.auth?.scope === "string" ? req.auth.scope.split(/\s+/) : [];
    const hasAllScopes = scopes.every((scope) => granted.includes(scope));

    if (!hasAllScopes) {
      return res.status(403).json({ error: "insufficient_scope" });
    }

    return next();
  };
}

function requireRole(role) {
  return (req, res, next) => {
    const roles = req.auth?.["https://example.com/roles"];

    if (!Array.isArray(roles) || !roles.includes(role)) {
      return res.status(403).json({ error: "insufficient_role" });
    }

    return next();
  };
}

module.exports = {
  requireAuth,
  requireScopes,
  requireRole
};
