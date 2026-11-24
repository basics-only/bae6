import { Authn } from "@bae6/authn";
import {
  executionContextOf,
  nodeMiddleware,
  tenantGuard,
} from "@bae6/authz/middleware";
import express from "express";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const authn = new Authn({
  baseUrl: required("BAE6_AUTHN_URL"),
  credentials: required("BAE6_AUTHN_CLIENT_SECRET"),
});
const guard = tenantGuard({
  authz: {
    baseUrl: required("BAE6_API_URL"),
    application: "node-protected-api",
  },
  includeExecutionContext: true,
  exchange: (subjectToken) =>
    authn.exchangeToken({
      subjectToken,
      subjectTokenType: "jwt",
      audience: "bae6-authz",
    }),
});

const app = express();
app.get(
  "/documents/:id",
  nodeMiddleware(guard, (req) => ({
    resourceType: "document",
    resourceId: req.params.id,
  })),
  (req, res) => {
    const context = executionContextOf(req);
    if (!context) return res.sendStatus(503);
    return res.json({ id: req.params.id, requestId: context.requestId });
  },
);
app.listen(Number(process.env.PORT ?? 8102), "127.0.0.1");
