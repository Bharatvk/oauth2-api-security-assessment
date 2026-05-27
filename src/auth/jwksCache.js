"use strict";

const { JwksFetchError } = require("./errors");

const DEFAULT_TTL_SECONDS = 600;
const MIN_FORCED_REFRESH_SECONDS = 30;
const NEGATIVE_CACHE_SECONDS = 30;

const caches = new Map();

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function getState(jwksUri) {
  if (!caches.has(jwksUri)) {
    caches.set(jwksUri, {
      keys: null,
      expiresAt: 0,
      lastForcedRefreshAt: 0,
      negativeKids: new Map()
    });
  }
  return caches.get(jwksUri);
}

async function fetchJwks(jwksUri) {
  let response;
  try {
    response = await fetch(jwksUri);
  } catch (err) {
    throw new JwksFetchError("JWKS endpoint could not be reached");
  }

  if (!response || !response.ok) {
    throw new JwksFetchError("JWKS endpoint returned an error");
  }

  let body;
  try {
    body = await response.json();
  } catch (err) {
    throw new JwksFetchError("JWKS response was not valid JSON");
  }

  if (!body || !Array.isArray(body.keys)) {
    throw new JwksFetchError("JWKS response did not include keys");
  }

  return body.keys;
}

function findKey(keys, kid) {
  return keys.find((key) => key && key.kid === kid);
}

function isNegativelyCached(state, kid, now) {
  const expiresAt = state.negativeKids.get(kid);
  if (!expiresAt) {
    return false;
  }
  if (expiresAt <= now) {
    state.negativeKids.delete(kid);
    return false;
  }
  return true;
}

async function getSigningKey(kid, options) {
  const jwksUri = options.jwksUri;
  const ttlSeconds = options.jwksCacheTtlSeconds || DEFAULT_TTL_SECONDS;
  const now = nowSeconds();
  const state = getState(jwksUri);

  if (!state.keys || state.expiresAt <= now) {
    state.keys = await fetchJwks(jwksUri);
    state.expiresAt = now + ttlSeconds;
    state.negativeKids.clear();
  }

  let key = findKey(state.keys, kid);
  if (key) {
    return key;
  }

  if (isNegativelyCached(state, kid, now)) {
    return null;
  }

  if (now - state.lastForcedRefreshAt >= MIN_FORCED_REFRESH_SECONDS) {
    state.lastForcedRefreshAt = now;
    state.keys = await fetchJwks(jwksUri);
    state.expiresAt = now + ttlSeconds;
    key = findKey(state.keys, kid);
    if (key) {
      return key;
    }
  }

  state.negativeKids.set(kid, now + NEGATIVE_CACHE_SECONDS);
  return null;
}

// Test-only helper: keeps unit tests deterministic without exposing cache controls to callers.
function _clearJwksCacheForTests() {
  caches.clear();
}

module.exports = {
  getSigningKey,
  _clearJwksCacheForTests
};
