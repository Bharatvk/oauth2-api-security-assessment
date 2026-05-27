"use strict";

const express = require("express");
const { createDocumentsRouter } = require("./api/documents");

function createApp(authOptions) {
  const app = express();

  app.use(express.json());
  app.use("/api", createDocumentsRouter(authOptions));

  return app;
}

function readAuthOptionsFromEnv(env) {
  const required = ["JWKS_URI", "ISSUER", "AUDIENCE"];
  const missing = required.filter((key) => !env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required auth configuration: ${missing.join(", ")}`);
  }

  return {
    jwksUri: env.JWKS_URI,
    issuer: env.ISSUER,
    audience: env.AUDIENCE
  };
}

if (require.main === module) {
  const authOptions = readAuthOptionsFromEnv(process.env);
  const port = process.env.PORT || 3000;
  const app = createApp(authOptions);

  app.listen(port, () => {
    console.log(`Listening on port ${port}`);
  });
}

module.exports = {
  createApp,
  readAuthOptionsFromEnv
};
