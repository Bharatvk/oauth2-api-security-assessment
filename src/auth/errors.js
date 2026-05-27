"use strict";

class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
  }
}

class MalformedTokenError extends AuthError {}
class UnsupportedAlgorithmError extends AuthError {}
class UnknownKeyError extends AuthError {}
class InvalidSignatureError extends AuthError {}
class TokenExpiredError extends AuthError {}
class TokenNotYetValidError extends AuthError {}
class IssuerMismatchError extends AuthError {}
class AudienceMismatchError extends AuthError {}
class JwksFetchError extends AuthError {}

module.exports = {
  AuthError,
  MalformedTokenError,
  UnsupportedAlgorithmError,
  UnknownKeyError,
  InvalidSignatureError,
  TokenExpiredError,
  TokenNotYetValidError,
  IssuerMismatchError,
  AudienceMismatchError,
  JwksFetchError
};
