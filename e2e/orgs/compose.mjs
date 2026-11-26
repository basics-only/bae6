// Reads `compose config --format json` on stdin and prints an override adding ORGS to it.
import { readFileSync } from "node:fs";
import { ORGS, orgIssuer } from "./orgs.mjs";

const base = JSON.parse(readFileSync(0, "utf8")).services;
const oidc = "http://mock-oidc:8080";
const env = (service, key) => JSON.parse(base[service].environment[key]);
const issuers = (service, key, audience) => [
  ...env(service, key),
  ...ORGS.map((organization) => ({
    issuer: orgIssuer(oidc, organization),
    audience,
    jwksUri: `${orgIssuer(oidc, organization)}/.well-known/jwks.json`,
    organization,
    application: "demo",
  })),
];

const services = {};
if (base["data-api"]) {
  const config = env("data-api", "BAE6_DATA_CONFIG");
  const [example] = config.sources;
  for (const organization of ORGS) {
    config.sources.push({
      ...example,
      organization,
      prefix: `${organization}/`,
    });
  }
  const objects = env("mock-cloud", "MOCK_S3_OBJECTS");
  for (const org of ORGS)
    objects.docs[`${org}/handbook.txt`] = `Handbook of ${org}.`;
  services["data-api"] = {
    environment: {
      BAE6_DATA_ISSUERS: JSON.stringify(
        issuers("data-api", "BAE6_DATA_ISSUERS", "bae6-context-data"),
      ),
      BAE6_DATA_CONFIG: JSON.stringify(config),
    },
  };
  services["mock-cloud"] = {
    environment: { MOCK_S3_OBJECTS: JSON.stringify(objects) },
  };
}

console.log(JSON.stringify({ services }));
