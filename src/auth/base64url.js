"use strict";

function decodeBase64Url(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Invalid base64url input");
  }

  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url characters");
  }

  if (value.length % 4 === 1) {
    throw new Error("Invalid base64url length");
  }

  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  return Buffer.from(base64 + "=".repeat(padding), "base64");
}

module.exports = { decodeBase64Url };
